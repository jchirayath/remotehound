# syntax=docker/dockerfile:1.7
# =============================================================================
# Apache Guacamole 1.6.0 web application, slimmed and patched for RemoteHound.
#
# Why not the stock guacamole/guacamole:1.6.0 image: it is built on Tomcat
# 9.0.106 and ships every extension (LDAP, vault, SSO, Duo, JDBC drivers …),
# whose bundled libraries carry 18 critical / 120 high CVEs (trivy, Nov 2026).
# 1.6.0 is still the newest Guacamole release, so this image keeps Guacamole
# itself byte-for-byte and changes only what is around it:
#
#   * a current Tomcat 9 base (digest-pinned) instead of 9.0.106;
#   * only the one extension RemoteHound uses: guacamole-auth-json;
#   * Jackson 2.19.0 and Guava 32.1.3 — in the WAR and in guacamole-auth-json —
#     replaced with patched releases from Maven Central, each pinned by SHA-256
#     (ADD --checksum).
#
# Startup is unchanged: Apache's own entrypoint scripts and environment
# variables (GUACD_HOSTNAME, JSON_ENABLED, JSON_SECRET_KEY, …), the same uid.
#
# Build (from the repo root):  docker build -t rh-guacamole:1.6.0 deploy/guacamole
# Check:                       trivy image rh-guacamole:1.6.0
# =============================================================================

ARG UPSTREAM=guacamole/guacamole:1.6.0@sha256:f344085e618bb05e22b964b0208dbd06d3468275bac70206f93805245e067b40
ARG TOMCAT=tomcat:9.0-jre21-temurin-noble@sha256:4bcd87e970a44db45e3d1cdd3a7659114940f89d01c8f8605fa048fb3943c4e3

FROM ${UPSTREAM} AS upstream

# --- repack the WAR with patched libraries -----------------------------------
FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f AS war
RUN apk add --no-cache zip unzip
WORKDIR /work
COPY --from=upstream /opt/guacamole/webapp/guacamole.war guacamole.war
ADD --checksum=sha256:8c5623b98f32d5f7e1287ff61ed50e08ab7b11381e991fff89327faabba42261 \
    https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-core/2.21.7/jackson-core-2.21.7.jar WEB-INF/lib/
ADD --checksum=sha256:1290c2795e93e8a6861a6c4d9ff0d844d32f5ea178362cb2721edf5561e828b1 \
    https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-databind/2.21.7/jackson-databind-2.21.7.jar WEB-INF/lib/
ADD --checksum=sha256:53ca085f4a150f703f49e1aabd935bd03b43e1ea3d55d135438292af22cef56b \
    https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-annotations/2.21/jackson-annotations-2.21.jar WEB-INF/lib/
ADD --checksum=sha256:a74597f82779d79e89ad9b3fdce3558607301537e624e4db13f64925186ac0c5 \
    https://repo1.maven.org/maven2/com/fasterxml/jackson/module/jackson-module-jaxb-annotations/2.21.7/jackson-module-jaxb-annotations-2.21.7.jar WEB-INF/lib/
ADD --checksum=sha256:b530942257fb935f8b2cfaa5f8eb5bd59c555fd8e8d01b8ce98912e077ea606c \
    https://repo1.maven.org/maven2/com/google/guava/guava/33.7.2-jre/guava-33.7.2-jre.jar WEB-INF/lib/
ADD --checksum=sha256:cbfc3906b19b8f55dd7cfd6dfe0aa4532e834250d7f080bd8d211a3e246b59cb \
    https://repo1.maven.org/maven2/com/google/guava/failureaccess/1.0.3/failureaccess-1.0.3.jar WEB-INF/lib/
# Fail the build if the WAR's library set is not what this file expects, so a
# changed upstream image cannot silently keep an old jar next to a new one.
RUN set -eu; \
    old="WEB-INF/lib/jackson-core-2.19.0.jar WEB-INF/lib/jackson-databind-2.19.0.jar \
         WEB-INF/lib/jackson-annotations-2.19.0.jar WEB-INF/lib/jackson-module-jaxb-annotations-2.19.0.jar \
         WEB-INF/lib/guava-32.1.3-jre.jar WEB-INF/lib/failureaccess-1.0.1.jar"; \
    for j in $old; do unzip -l guacamole.war "$j" >/dev/null || { echo "missing $j in upstream WAR" >&2; exit 1; }; done; \
    zip -q -d guacamole.war $old; \
    zip -q -0 guacamole.war WEB-INF/lib/*.jar; \
    n=$(unzip -l guacamole.war | grep -cE 'WEB-INF/lib/(jackson|guava|failureaccess)'); \
    [ "$n" = 6 ] || { echo "expected 6 patched jars, found $n" >&2; exit 1; }
# guacamole-auth-json bundles its own copies as top-level nested jars (loaded
# by Guacamole's extension classloader); swap those the same way.
COPY --from=upstream /opt/guacamole/extensions/guacamole-auth-json/guacamole-auth-json.jar auth-json.jar
RUN set -eu; \
    old="jackson-core-2.19.0.jar jackson-databind-2.19.0.jar jackson-annotations-2.19.0.jar \
         guava-32.1.3-jre.jar failureaccess-1.0.1.jar"; \
    for j in $old; do unzip -l auth-json.jar "$j" >/dev/null || { echo "missing $j in auth-json" >&2; exit 1; }; done; \
    zip -q -d auth-json.jar $old; \
    cd WEB-INF/lib && zip -q -0 ../../auth-json.jar jackson-core-2.21.7.jar jackson-databind-2.21.7.jar \
        jackson-annotations-2.21.jar guava-33.7.2-jre.jar failureaccess-1.0.3.jar && cd /work; \
    n=$(unzip -l auth-json.jar | grep -cE ' (jackson|guava|failureaccess)[^/]*\.jar$'); \
    [ "$n" = 5 ] || { echo "expected 5 patched jars in auth-json, found $n" >&2; exit 1; }

# --- runtime -------------------------------------------------------------------
FROM ${TOMCAT}
ENV GUACAMOLE_HOME=/etc/guacamole \
    ENABLE_FILE_ENVIRONMENT_PROPERTIES=true
RUN groupadd --system --gid 1001 guacamole \
 && useradd --system --uid 1001 --gid 1001 --home-dir /home/guacamole --create-home --shell /usr/sbin/nologin guacamole \
 && rm -rf /usr/local/tomcat/webapps/* /usr/local/tomcat/webapps.dist
COPY --from=upstream /opt/guacamole/bin /opt/guacamole/bin
COPY --from=upstream /opt/guacamole/entrypoint.d /opt/guacamole/entrypoint.d
COPY --from=upstream /opt/guacamole/extensions/guacamole-auth-json /opt/guacamole/extensions/guacamole-auth-json
COPY --from=upstream /opt/guacamole/environment/JSON_ /opt/guacamole/environment/JSON_
COPY --from=war /work/guacamole.war /opt/guacamole/webapp/guacamole.war
COPY --from=war /work/auth-json.jar /opt/guacamole/extensions/guacamole-auth-json/guacamole-auth-json.jar
USER guacamole
WORKDIR /opt/guacamole
EXPOSE 8080
CMD ["/opt/guacamole/bin/entrypoint.sh"]
