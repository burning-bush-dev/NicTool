# CI container image for GitHub Actions
#
# Pre-installs all system and CPAN dependencies so the CI job only needs to
# install the checked-out NicTool code itself (fast, deps already cached).
#
# Built and pushed by .github/workflows/ci-image.yml → ghcr.io

FROM debian:bookworm

ENV DEBIAN_FRONTEND=noninteractive LANG=en_US.UTF-8 LC_ALL=C.UTF-8

RUN apt-get -q update && apt-get install -qy \
      perl \
      cpanminus \
      build-essential \
      apache2 \
      libapache2-mod-perl2 \
      libapache2-mod-perl2-dev \
      libxml2 \
      libssl-dev \
      libmariadb-dev \
      expat \
      libexpat-dev \
      gettext \
      bind9utils \
      default-mysql-client \
      openssl \
      libdbix-simple-perl \
      libdbd-mysql-perl \
      libapache-dbi-perl \
      libnet-ip-perl \
      libxml-libxml-perl \
      libxml-parser-perl \
      libdigest-hmac-perl \
      libjson-perl \
      librpc-xml-perl \
      libsoap-lite-perl \
      libmodule-build-perl \
      libmime-base32-perl \
      libmime-base64-perl \
      libbind-confparser-perl \
      libcrypt-openssl-rsa-perl \
      libcrypt-openssl-dsa-perl \
      libnet-dns-perl \
      libyaml-perl \
      libwww-perl \
      liburi-perl \
      libmime-tools-perl \
      libmailtools-perl \
      libfile-sharedir-perl \
      libdbi-perl \
      libcgi-pm-perl \
      libtest-pod-perl \
      libtest-output-perl \
      libtest-simple-perl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Copy only Makefile.PL files for CPAN dependency resolution (cached layer)
COPY server/Makefile.PL /tmp/nictool/server/Makefile.PL
COPY client/Makefile.PL /tmp/nictool/client/Makefile.PL

# Install CPAN dependencies (rebuilds only when Makefile.PL changes)
RUN cd /tmp/nictool/server && perl Makefile.PL && cpanm -n . \
    && cd /tmp/nictool/client && perl Makefile.PL && cpanm -n . \
    && rm -rf /tmp/nictool

# Additional Perl modules not declared in Makefile.PL
RUN cpanm --notest \
    CryptX Crypt::Mac::HMAC Crypt::KeyDerivation \
    Test::HTML::Lint Time::TAI64 DBD::MariaDB \
    Net::LDAP Test::Output

# Configure Apache for mod_perl (requires prefork MPM)
RUN a2dismod mpm_event && a2enmod mpm_prefork && a2enmod ssl \
    && rm -rf /etc/apache2/sites-enabled/* /etc/apache2/sites-available/*
