from diagrams import Cluster, Diagram, Edge, Node
from diagrams.aws.management import Cloudwatch
from diagrams.aws.storage import ElasticBlockStoreEBSSnapshot
from diagrams.aws.storage import SimpleStorageServiceS3 as S3
from diagrams.azure.database import SQLServers
from diagrams.azure.general import Helpsupport
from diagrams.azure.identity import Users
from diagrams.gcp.operations import Monitoring
from diagrams.oci.monitoring import Notifications
from diagrams.onprem.container import Docker
from diagrams.onprem.workflow import Airflow

with Diagram(
    "Deployment Architecture Diagram",
    show=False,
    direction="LR",
    graph_attr={"rankdir": "LR", "splines": "ortho"},
):
    ingress = Users("Team 04")
    with Cluster("Data Sources"):
        with Cluster("GEOS and NEXTRAD Services"):
            geos_bucket = ElasticBlockStoreEBSSnapshot("GEOS Bucket")
            nextrad_bucket = ElasticBlockStoreEBSSnapshot("NEXTRAD Bucket")

    with Cluster("Docker Compose FastAPI"):
        with Cluster("App"):
            userfacing = Docker("Streamlit")
            backend = Docker("FastAPI")

        with Cluster("Sqlite Database"):
            user_db = SQLServers("Users DB")

        with Cluster("AWS services"):
            cloudwatch = Cloudwatch("AWS Logs")
            aws_bucket = ElasticBlockStoreEBSSnapshot("S3 Bucket")

        with Cluster("GCP Bucket"):
            metadata_db = SQLServers("MetaData DB")

    with Cluster("Docker Compose Airflow"):

        class DAG(Airflow):
            _type = "DAG"

        with Cluster("GEOS Airflow"):
            GEOS_DAG = DAG("GEOS DAG")

        with Cluster("NEXTRAD Airflow"):
            NEXTRAD_DAG = DAG("NEXTRAD DAG")

    userfacing << Edge(label="REST API Request", color="black") << backend
    backend << Edge(label="Response", color="black") << userfacing

    user_db << Edge(label="JWT Authorization") << backend
    aws_bucket << Edge(label="Copy Files Request") << backend
    cloudwatch << Edge(label="Download Logging") << backend

    (
        backend
        << Edge(label="Data Fetch on Request Received from Streamlit")
        << metadata_db
    )

    metadata_db << Edge(label="Update GEOS MetaData on Every Run") << GEOS_DAG
    metadata_db << Edge(label="Update NextRAD MetaData on Every Run") << NEXTRAD_DAG

    GEOS_DAG << Edge(label="Fetches GEOS MetaData on On Every Run") << geos_bucket
    (
        NEXTRAD_DAG
        << Edge(label="Fetches NextRAD MetaData on On Every Run")
        << nextrad_bucket
    )
