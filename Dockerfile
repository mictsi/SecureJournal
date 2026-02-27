FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY ["SecureJournal.Web/SecureJournal.Web.csproj", "SecureJournal.Web/"]
COPY ["SecureJournal.Core/SecureJournal.Core.csproj", "SecureJournal.Core/"]
RUN dotnet restore "SecureJournal.Web/SecureJournal.Web.csproj"

COPY . .
RUN dotnet publish "SecureJournal.Web/SecureJournal.Web.csproj" -c Release -o /app/publish --no-restore /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app

ARG APP_UID=10001
ARG APP_GID=10001

RUN groupadd --gid ${APP_GID} appgroup \
    && useradd --uid ${APP_UID} --gid ${APP_GID} --create-home --home-dir /home/appuser --shell /usr/sbin/nologin appuser \
    && mkdir -p /data /app/logs \
    && chown -R appuser:appgroup /app /data /home/appuser

ENV ASPNETCORE_URLS=http://+:8080
ENV ASPNETCORE_ENVIRONMENT=Production

EXPOSE 8080

COPY --from=build /app/publish .
RUN chown -R appuser:appgroup /app

USER appuser
ENTRYPOINT ["dotnet", "SecureJournal.Web.dll"]
