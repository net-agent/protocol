@echo off

SET distdir="..\dist"
SET clientname="xess_c"
SET servername="vmess_s"
SET version=%1

if "%version%" == "" (

  echo invalid version info

) else (

  echo version=%version%

  if not exist "dist" mkdir dist
  if not exist "dist\%version%" mkdir "dist\%version%"


  echo start build linux(amd64) 
  set CGO_ENABLE=0
  set GOOS=linux
  set GOARCH=amd64

  echo build agent
  cd client
  go build -o "%distdir%\%version%\%clientname%_linux_%version%_bin"

  echo build server
  cd ..\server
  go build -o "%distdir%\%version%\%servername%_linux_%version%_bin"

  cd ..
  echo linux(amd64) finished



  echo start build linux(darwin)
  set CGO_ENABLE=0
  set GOOS=darwin
  set GOARCH=amd64

  echo build agent
  cd client
  go build -o "%distdir%\%version%\%clientname%_darwin_%version%_bin"

  echo build server
  cd ..\server
  go build -o "%distdir%\%version%\%servername%_darwin_%version%_bin"

  cd ..
  echo linux(darwin) finished


  echo start build windows
  set CGO_ENABLE=0
  set GOOS=windows
  set GOARCH=amd64

  echo build agent
  cd client
  go build -o "%distdir%\%version%\%clientname%_windows_%version%.exe"

  echo build server
  cd ..\server
  go build -o "%distdir%\%version%\%servername%_windows_%version%.exe"

  cd ..
  echo windows finished
)
