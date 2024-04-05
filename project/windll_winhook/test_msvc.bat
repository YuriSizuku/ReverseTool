msbuild %~dp0\libwinhook.sln -t:libwinhook_test:rebuild -p:configuration=debug -p:Platform=x86 
msbuild %~dp0\libwinhook.sln -t:libwinhook_test:rebuild -p:configuration=debug -p:Platform=x64
pushd %~dp0\build
libwinhook_test32d
libwinhook_test64d
popd