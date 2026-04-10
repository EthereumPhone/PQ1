To build the tls_client example program:

cmake ../.
cmake --build .

Remarks
(1) Build options will match the features of the installed libraries under 
    /usr/local/lib.
    This is achieved by including /usr/local/share/se05x/cmake_options_installed.cmake
    in ../CMakeLists.txt
(2) You can build against either the static (*.a) or shared libaries (*.so). Ensure these
    are installed on /usr/local/lib
(3) When building against shared libraries [default] you may have to issue the following
    command first:
    
    (sudo) ldconfig /usr/local/lib
