# ssh3-server rpm spec - packaged by packaging/build.sh, which copies this
# template into the rpmbuild tree with @VERSION@ substituted from the binary
# (-V output). the payload is the prebuilt ssh3-server binary: %prep/%build
# are intentionally empty, rpmbuild only wraps it.
#
# target: fedora/rhel-style systems with openssl-libs >= 3.5 (the QUIC TLS
# API). older fedoras carry 3.0.x/3.2.x and cannot run this daemon.

Name:           ssh3-server
Version:        @VERSION@
Release:        1%{?dist}
Summary:        SSH3 server - SSH over QUIC/HTTP3 transport
License:        BSD-2-Clause
BuildArch:      x86_64

Source0:        ssh3-server
Source1:        LICENSE
Source2:        THIRD-PARTY-NOTICES.md
Source3:        README.md

Requires:       openssl-libs >= 3.5
Conflicts:      ssh3-go-client
Conflicts:      ssh3-go-server
# the rpm spelling of the deb Replaces: the files move under these names
Obsoletes:      ssh3-go-client
Obsoletes:      ssh3-go-server

%description
SSH3 server daemon: the SSH3 protocol carried over HTTP/3 (QUIC),
implemented in C in the nginx style on top of the OpenSSL QUIC TLS API
(OpenSSL >= 3.5). Configured through environment variables and
command-line flags; drops privileges to the system user "ssh3" with
state under /var/lib/ssh3.

%prep
# an empty scratch build directory, the sources are copied in manually
%setup -c -T
cp %{SOURCE1} %{SOURCE2} %{SOURCE3} .

%build
# nothing to build: the payload is the prebuilt binary

%install
mkdir -p %{buildroot}%{_sbindir}
install -m 0755 %{SOURCE0} %{buildroot}%{_sbindir}/ssh3-server

%files
%license LICENSE THIRD-PARTY-NOTICES.md
%doc README.md
%attr(0755,root,root) %{_sbindir}/ssh3-server

%changelog
* Mon Oct 05 2026 ssh3-c maintainers <maintainers@example.com> - @VERSION@-1
- initial packaging
