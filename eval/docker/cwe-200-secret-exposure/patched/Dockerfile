# Fixed: Uses BuildKit secret mount instead of ARG→ENV.
# The token never persists in any layer.

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /app
COPY . .

# ok: cwe-200-arg-env-secret — secret is mounted, not persisted
RUN --mount=type=secret,id=feed_token \
    VSS_NUGET_EXTERNAL_FEED_ENDPOINTS="{\"endpointCredentials\": [{\"endpoint\":\"https://pkgs.dev.azure.com/org/_packaging/feed/nuget/v3/index.json\", \"username\":\"docker\", \"password\":\"$(cat /run/secrets/feed_token)\"}]}" \
    dotnet restore && dotnet publish -c Release -o /app/dist

FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app/dist .
EXPOSE 8080
ENTRYPOINT ["./MyApp"]
