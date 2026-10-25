FROM mcr.microsoft.com/dotnet/sdk:10.0.402 AS build
WORKDIR /src

COPY ["global.json", "Directory.Build.props", "Directory.Packages.props", "./"]
COPY ["SecureJournal.Web/SecureJournal.Web.csproj", "SecureJournal.Web/packages.lock.json", "SecureJournal.Web/"]
COPY ["SecureJournal.Core/SecureJournal.Core.csproj", "SecureJournal.Core/packages.lock.json", "SecureJournal.Core/"]
RUN dotnet restore "SecureJournal.Web/SecureJournal.Web.csproj" --locked-mode

COPY . .
RUN dotnet publish "SecureJournal.Web/SecureJournal.Web.csproj" -c Release -o /app/publish --no-restore /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0.13-alpine3.24-extra AS final
WORKDIR /app

ARG APP_UID=10001
ARG APP_GID=10001

RUN addgroup -g ${APP_GID} appgroup \
    && adduser -D -H -u ${APP_UID} -G appgroup -h /home/appuser -s /sbin/nologin appuser \
    && mkdir -p /data /app/logs /home/appuser \
    && chown -R appuser:appgroup /app /data /home/appuser

ENV ASPNETCORE_URLS=http://+:8080
ENV ASPNETCORE_ENVIRONMENT=Production

EXPOSE 8080

COPY --from=build /app/publish .
RUN chown -R appuser:appgroup /app

USER appuser
ENTRYPOINT ["dotnet", "SecureJournal.Web.dll"]
