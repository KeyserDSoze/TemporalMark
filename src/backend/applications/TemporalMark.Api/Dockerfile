FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /workspace
COPY src/backend/ ./src/backend/
RUN dotnet publish src/backend/applications/TemporalMark.Api/TemporalMark.Api.csproj -c Release -o /publish

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /publish .
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
USER $APP_UID
ENTRYPOINT ["dotnet", "TemporalMark.Api.dll"]
