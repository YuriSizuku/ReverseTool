msbuild %~dp0\libwinpe.sln -t:libwinpe_test:rebuild -p:configuration=debug -p:Platform=x86 
msbuild %~dp0\libwinpe.sln -t:libwinpe_test:rebuild -p:configuration=debug -p:Platform=x64
pushd %~dp0\build
libwinpe_test32d
libwinpe_test64d
popd