Name:		putils
Version:	1.0
Release:	1%{?dist}
Summary:	Various Linux utilities using the /proc filesystem

Group:		Application/System
License:	GPLv2
URL:		https://github.com/drepper/putils
Source0:	%{name}-%{version}.tar.bz2

%description
The plimit utility allows to query and set the limits of a process.
The pfiles utility allows to examine the open files of a process.

%prep
%setup -q


%build
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc
%{_bindir}/pfiles
%{_bindir}/plimit


%changelog
* Thu May 31 2012 Ulrich Drepper <drepper@gmail.com> -
- Initial build.
