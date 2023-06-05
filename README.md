# locksmith
Locksmith seeks to solve a common problem in GCP organizations in which integrations with 3dP applications/services require a GCP service account key (Example services: [tenable](https://docs.tenable.com/cloud-security/Content/QuickReference/OnboardGCPServiceAccount.htm), [trend micro](https://cloudone.trendmicro.com/docs/workload-security/gcp-account-create/), [prisma](https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-admin/connect-your-cloud-platform-to-prisma-cloud/onboard-gcp/onboard-gcp-project)). Because this is a common pattern in GCP and service account keys present a risk due to their long-lived credentials, organizations are forced to make a tradeoff between rejecting a solution which may provide a genuine security service/improvement to their posture or rejecting the solution because of its reliance on service account keys. Because this is a common enough pattern in GCP there's a reasonable need to offer a stable, repeatable solution for addressing this tradeoff across an enterprise/GCP org.

A custom service such as locksmith removes the need to grant service account key permissions to developers and instead ensures that service account keys created in a given GCP Org are managed in a consistent manner.

Locksmith simplifies the management of service account keys in a few key ways:
1. It orchestrates creating, vaulting (placing in GCP Secrets Manager), rotating, and disabling of keys.
2. Because the management of the keys is eased, it becomes a low cost effort to frequently rotate the service account keys,
which reduces the primary issue with service account keys (the long-lived nature of the credential).
1. It provides a natural funnel/forcing mechanism to ensure all keys in a given org are managed consistently. Additionally, configurations
could be established to ensure keys are rotated within a certain time frame while easily notifying developer teams/applications that a new
version has been vaulted in secrets manager.
1. [Asset Key Thief](https://engineering.sada.com/asset-key-thief-disclosure-cfae4f1778b6) provides a clear example of how a misconfiguration
within other GCP services can force organizations to need to rapidly rotate all or some keys within their GCP environment. Locksmith can address
this situation easily with the _yet to be released_ emergency key rotation option.

## Deployment Configuration

The Service Account used to run the cloud function will require the following permissions: Secret Manager Admin and Service Account Key Admin.

A runtime environment variable of SecureStoreProjectID is expected to be provided and needs to contain a valid projectID in the form `my-project-id-123`

NOTE: The Identity and Access Management (IAM) and Secrets Manager APIs must be enabled in the projects where service account keys and secrets will be used.
