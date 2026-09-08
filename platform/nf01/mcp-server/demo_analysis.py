import asyncio
import json
from datetime import timedelta

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


SALES_CSV = """order_id,order_date,region,category,quantity,unit_price
O001,2026-08-01,Bangkok,Electronics,2,12500.00
O002,2026-08-01,North,Home,5,850.00
O003,2026-08-02,Bangkok,Home,3,1200.00
O004,2026-08-02,South,Electronics,1,18900.00
O005,2026-08-03,North,Electronics,4,3200.00
O006,2026-08-03,South,Home,8,650.00
O007,2026-08-04,Bangkok,Electronics,1,45000.00
O008,2026-08-04,North,Home,6,990.00
O009,2026-08-05,South,Electronics,3,7500.00
O010,2026-08-05,Bangkok,Home,10,450.00
O011,2026-08-06,North,Electronics,2,15900.00
O012,2026-08-06,South,Home,4,1750.00
"""

SPARK_CODE = '''from pyspark.sql import SparkSession
from pyspark.sql import functions as F

spark = SparkSession.builder.appName("mcp-sales-analysis").getOrCreate()
source = "hdfs://namenode:9000/mcp/data/sales.csv"
output = "hdfs://namenode:9000/mcp/analytics/sales_summary"

sales = (
    spark.read.option("header", True)
    .option("inferSchema", True)
    .csv(source)
    .withColumn("revenue", F.col("quantity") * F.col("unit_price"))
)

summary = (
    sales.groupBy("region", "category")
    .agg(
        F.countDistinct("order_id").alias("orders"),
        F.sum("quantity").alias("units"),
        F.round(F.sum("revenue"), 2).alias("revenue"),
        F.round(F.avg("revenue"), 2).alias("avg_order_value"),
    )
    .orderBy(F.desc("revenue"), "region", "category")
)

total_revenue = sales.agg(F.round(F.sum("revenue"), 2)).first()[0]
top = summary.first()
print(f"TOTAL_REVENUE={total_revenue}")
print(f"TOP_SEGMENT={top['region']} / {top['category']} / {top['revenue']}")
summary.show(truncate=False)
summary.coalesce(1).write.mode("overwrite").json(output)
spark.stop()
'''


def data(result):
    if result.isError:
        message = "\n".join(getattr(item, "text", str(item)) for item in result.content)
        raise RuntimeError(message)
    if result.structuredContent is not None:
        return result.structuredContent.get("result", result.structuredContent)
    return json.loads(result.content[0].text)


async def main():
    async with streamablehttp_client("http://127.0.0.1:8000/mcp") as streams:
        read_stream, write_stream, _ = streams
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            await session.call_tool("hdfs_mkdir", {"path": "/data"})
            uploaded = data(
                await session.call_tool(
                    "hdfs_write_text",
                    {
                        "path": "/data/sales.csv",
                        "text": SALES_CSV,
                        "overwrite": True,
                        "replication": 2,
                    },
                )
            )

            saved = data(
                await session.call_tool(
                    "spark_save_job",
                    {
                        "filename": "sales_analysis.py",
                        "code": SPARK_CODE,
                        "overwrite": True,
                    },
                )
            )
            validated = data(
                await session.call_tool(
                    "spark_validate_job", {"filename": "sales_analysis.py"}
                )
            )
            submitted = data(
                await session.call_tool(
                    "spark_submit_job",
                    {
                        "filename": "sales_analysis.py",
                        "conf": {
                            "spark.app.name": "mcp-sales-analysis",
                            "spark.sql.shuffle.partitions": "4",
                        },
                    },
                )
            )

            job_id = submitted["job_id"]
            status = submitted
            for _ in range(90):
                status = data(
                    await session.call_tool("spark_job_status", {"job_id": job_id})
                )
                if status["status"] != "RUNNING":
                    break
                await asyncio.sleep(1)
            if status["status"] != "SUCCEEDED":
                logs = data(
                    await session.call_tool(
                        "spark_job_logs", {"job_id": job_id, "tail_lines": 200}
                    )
                )
                raise RuntimeError(json.dumps({"status": status, "logs": logs}, indent=2))

            files = data(
                await session.call_tool(
                    "hdfs_list", {"path": "/analytics/sales_summary"}
                )
            )
            part = next(item["pathSuffix"] for item in files if item["pathSuffix"].startswith("part-"))
            result = data(
                await session.call_tool(
                    "hdfs_read_text",
                    {"path": f"/analytics/sales_summary/{part}", "max_bytes": 1048576},
                )
            )
            rows = [json.loads(line) for line in result["text"].splitlines() if line]
            logs = data(
                await session.call_tool(
                    "spark_job_logs", {"job_id": job_id, "tail_lines": 300}
                )
            )
            highlights = [
                line for line in logs["lines"]
                if line.startswith("TOTAL_REVENUE=") or line.startswith("TOP_SEGMENT=")
            ]
            print(
                json.dumps(
                    {
                        "upload": uploaded,
                        "spark_job_file": saved,
                        "validated": validated,
                        "job": status,
                        "highlights": highlights,
                        "result_path": "/mcp/analytics/sales_summary",
                        "summary": rows,
                    },
                    indent=2,
                    ensure_ascii=False,
                )
            )


if __name__ == "__main__":
    asyncio.run(asyncio.wait_for(main(), timeout=timedelta(minutes=3).total_seconds()))
