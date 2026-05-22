# Vulnerable: ARG→ENV persists build secret in image layer metadata.
# The FEED_ACCESSTOKEN is visible via `docker history` on the build stage.

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /app
COPY . .

# Support private NuGet feeds — token passed as build arg
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN curl -L https://raw.githubusercontent.com/Microsoft/artifacts-credprovider/master/helpers/installcredprovider.sh | sh

# ruleid: cwe-200-arg-env-secret
ARG FEED_ACCESSTOKEN
ENV VSS_NUGET_EXTERNAL_FEED_ENDPOINTS="{\"endpointCredentials\": [{\"endpoint\":\"https://pkgs.dev.azure.com/org/_packaging/feed/nuget/v3/index.json\", \"username\":\"docker\", \"password\":\"${FEED_ACCESSTOKEN}\"}]}"

RUN dotnet restore && dotnet publish -c Release -o /app/dist

# Final stage — clean, no secret
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app/dist .
EXPOSE 8080
ENTRYPOINT ["./MyApp"]
