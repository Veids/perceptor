# ---------- Common LLVM base ----------
FROM silkeh/clang:19 AS base
WORKDIR /app

# ---------- Build SsagePass (LLVM obfuscator) ----------
FROM base AS ssage

RUN apt-get update && apt-get install -y \
  git \
  libeigen3-dev \
  && rm -rf /var/lib/apt/lists/*

RUN git clone --single-branch --branch dev https://github.com/Veids/SsagePass.git
RUN cd SsagePass/Obfuscation && \
    cmake -S . -B build -DLT_LLVM_INSTALL_DIR=/usr/lib/llvm-19 -DCMAKE_BUILD_TYPE=release && \
    cmake --build build -j $(nproc)

# ---------- Build donut ----------
FROM debian:bookworm AS donut

RUN apt-get update
RUN apt-get install --no-install-recommends --no-install-suggests -y \
  mingw-w64 zip build-essential perl python3 xml2 pkg-config automake \
  libtool autotools-dev make g++ git ruby wget libssl-dev

WORKDIR /app
RUN git clone https://github.com/TheWover/donut.git
WORKDIR /app/donut
RUN make -f Makefile

# ---------- Grab PowerShell assemblies from mono ----------
FROM mono:latest AS mono

WORKDIR /app
RUN nuget install System.Management.Automation -DependencyVersion Ignore
RUN find . -iname '*.dll' -path '*/runtimes/unix/*' \
  -exec cp {} /app/ \;

# ---------- Final runtime ----------
FROM base AS final

RUN apt-get update && apt-get install -y \
  imagemagick \
  python3 \
  && rm -rf /var/lib/apt/lists/*

COPY --from=ssage /app/SsagePass/Obfuscation/build/libSsageObfuscator.so /opt/libSsageObfuscator.so
COPY --from=donut /app/donut/donut /opt/donut
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
COPY --from=mono /app/System.Management.Automation.dll /opt/System.Management.Automation.dll

RUN ln -s /usr/bin/python3 /usr/local/bin/python3.11

RUN wget https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb -O packages-microsoft-prod.deb && \
  dpkg -i packages-microsoft-prod.deb && \
  rm packages-microsoft-prod.deb

RUN apt-get update && apt-get install -y \
  git \
  mingw-w64 \
  osslsigncode \
  libmono-cecil-cil \
  dotnet-sdk-8.0 \
  && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/tpoechtrager/wclang && \
    cmake -S wclang -B ./wclang/build && \
    cd wclang/build && \
    make && make install && \
    cd /app && rm -rf wclang

RUN apt-get update && apt-get install -y \
  python3 \
  python3-dev \
  gcc \
  g++ \
  && rm -rf /var/lib/apt/lists/*

COPY README.md pyproject.toml uv.lock* ./

RUN uv sync --locked --python 3.11 --no-dev

COPY . .

RUN uv sync --locked --python 3.11 --no-dev

RUN uv tool install . --python 3.11

ENV PATH="/root/.local/bin/:$PATH"
