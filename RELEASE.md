# release cmon-proxy to docker hub

## Make sure you are logged in into docker hub

Enter credentials

    docker login

## Build frontend docker image locally

 NOTE: For this you gonna need gcloud login enabled also in your docker instance
 to be able to pull our private docker images used for building.
 Make sure you logged in using gcloud auth login as the session ends in 24hrs.

    cd cmon-proxy-fe
    make build-host

## Pull built frontend files

    cd cmon-proxy
    make getfrontendfiles

## Build the docker image

    make build

## Optionally make sure it works on your local

    docker run -p 19051:19051 severalnines/cmon-proxy

 And check https://localhost:19051 in your browser, make sure you accept the
 self-signed cert.

## Release to docker hub

    docker push severalnines/clustercontrol-manager:latest


