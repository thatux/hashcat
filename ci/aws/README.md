# Weekly CUDA GPU CI on AWS EC2

`.github/workflows/test_cuda.yml` runs the same test suite as `.github/workflows/test.yml`, but on real NVIDIA GPUs with the CUDA backend instead of the CPU through PoCL (issue #4941). It runs the work on AWS EC2 spot GPU instances for the length of the run and terminates them afterwards. This is the AWS sibling of the vast.ai launcher; the queue, worker-reuse, streaming and per-kind `test.py` commands are identical, only the provider layer is EC2.

## How it works

The workflow runs on a normal GitHub runner. `ci/aws/weekly_gpu.py` builds one shared queue of (mode, kind) tasks from the same mode pools `test.yml` uses (via `.github/workflows/ci_matrix.py`) and launches a set of GPU instances. Each instance clones hashcat at the commit under test, builds it, installs the oracles (pyenv, as `tools/install_modules.sh` does), then pulls tasks from the queue and runs `tools/test.py` for each with `-D 2` (the GPU device type) in place of `-D 1`. A free instance takes the next task, so the load balances itself; an instance that dies mid-task puts the task back on the queue for another. The one kind it does not run is the Python bridge.

Instances launch from a Deep Learning AMI (resolved through an SSM public parameter), which already carries the NVIDIA driver (`libcuda`) and the CUDA toolkit (`libnvrtc`), so no docker image is needed. They are spot instances of whichever of a few single-GPU types is cheapest right now (T4, A10G, L4). A short health probe right after boot drops an instance that is unreachable or has no visible GPU and launches another. Each task runs under a timeout, each task's output streams back as it finishes, and the instances are terminated as the queue drains and by an always-run cleanup job.

## There is no single "AWS token"

AWS authenticates with an **access key id and a secret access key**, plus a **region** (or an attached IAM role). Set them the standard boto3 way:

- `AWS_ACCESS_KEY_ID` (secret)
- `AWS_SECRET_ACCESS_KEY` (secret)
- `AWS_REGION` (variable, e.g. `us-east-1`)

Create the two secrets under **Settings -> Secrets and variables -> Actions**, and `AWS_REGION` as a variable there. The IAM user or role needs, scoped to this use:

- `ec2:RunInstances`, `ec2:TerminateInstances`, `ec2:DescribeInstances`, `ec2:DescribeSpotPriceHistory`
- `ec2:ImportKeyPair`, `ec2:DeleteKeyPair`, `ec2:CreateSecurityGroup`, `ec2:DescribeSecurityGroups`, `ec2:AuthorizeSecurityGroupIngress`, `ec2:CreateTags`
- `ssm:GetParameter` (to resolve the Deep Learning AMI)

Optional repository variables tune the rest without touching the workflow:

- `AWS_INSTANCE_TYPES`: comma list of single-GPU instance types, cheapest spot used, default `g4dn.2xlarge,g5.2xlarge,g6.2xlarge`.
- `AWS_MAX_PRICE`: most $/hour to bid per spot instance, default `0.60`.
- `AWS_AMI`: pin an AMI id; empty resolves the Deep Learning GPU AMI through SSM.

## Running it

From the **Actions** tab, pick **test-cuda** and **Run workflow**; the form chooses the modes, which kinds, and how many instances to run in parallel. It also runs on a weekly schedule, which only fires on the hashcat/hashcat repository. Locally, with the AWS environment set and `boto3` installed (`pip install boto3`):

    python ci/aws/weekly_gpu.py --modes "0 100 1000"      # a few modes
    python ci/aws/weekly_gpu.py --dry-run                  # print the plan and the scripts, launch nothing

`--dry-run` needs no AWS access.

## Cost

A full weekly run of the exhaustive suite is on the order of 100+ GPU-hours. On spot GPU instances that is roughly $15 to $25 depending on type and region; a lighter pass (for example `-a all -t single`) is a fraction of that. Spot is about a third of on-demand; if spot capacity is short the launcher moves to the next type.

## Security

The workflow triggers on the weekly schedule and manual dispatch only, never on pull requests, so the AWS credentials are never exposed to a fork's code. `permissions: contents: read`. The credentials stay on the GitHub runner and are never sent to an instance; each run imports a throwaway SSH key pair for reaching its instances and deletes it at the end. Instances are terminated on success, on failure, and on cancel.

## Status

Implemented against the boto3/EC2 API but not yet validated against a live AWS account. The parts to check first are the box-side assumptions (the AMI logs in as `ubuntu`, `apt` needs `sudo`, the CUDA toolkit is under `/usr/local/cuda`) and that the IAM policy above is sufficient. The vast.ai launcher in the `ci_testcuda_vastai` branch is the one that has run end to end.
