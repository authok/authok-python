# Deploy to https://pypi.org/project/authok-python/
# Requires a ~/.pypirc file in the developer machine with proper credentials

#!/usr/bin/env bash
docker build -t authok-python-sdk-publish .
docker run -it authok-python-sdk-publish
