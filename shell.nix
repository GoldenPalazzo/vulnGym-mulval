{ pkgs ? import <nixpkgs> {} }:

let
  thHome = let e = builtins.getEnv "TH_HOME"; in if e != "" then e else toString ./..;
in
(pkgs.buildFHSEnv {
  name = "mulval-env";
  targetPkgs = pkgs: with pkgs; [
    gcc
    zlib
    gnumake
    gnused
    coreutils
    autoconf
    bison
    flex
    perl
    git
    graphviz
    libxml2 # richiesto da XPath support in XSB
    makedepend # speedup build xsb
    pcre
    pcre.dev
    curl
    curl.dev
    texlive.combined.scheme-basic
    jdk8
    (python311.withPackages (ps: with ps; [
      find-libpython
      pip
      setuptools
    ]))
  ];

  runScript = "bash";

  profile = ''
    export TH_HOME=${thHome}
    export XSB_HOME=$TH_HOME/XSB
    export MULVALROOT=$TH_HOME/mulval
    export JAVA_HOME=${pkgs.jdk8}/lib/openjdk
    export PATH=$MULVALROOT/utils:$MULVALROOT/bin:$XSB_HOME/bin:$PATH
    mkdir -p $TH_HOME/.jni_fix
    cp $JAVA_HOME/include/*.h $JAVA_HOME/include/linux/*.h $TH_HOME/.jni_fix/ 2>/dev/null || true
    export C_INCLUDE_PATH=${pkgs.python311}/include/python3.11:$TH_HOME/.jni_fix:$C_INCLUDE_PATH
    export CPATH=$C_INCLUDE_PATH
  '';
}).env
