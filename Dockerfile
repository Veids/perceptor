FROM silkeh/clang:17 AS base
WORKDIR /app

FROM base as ssage

RUN apt-get update && apt-get install -y \
  git \
  libeigen3-dev \
  && rm -rf /var/lib/apt/lists/*

RUN git clone --single-branch --branch dev https://github.com/Veids/SsagePass.git
RUN cd SsagePass/Obfuscation && \
    cmake -S . -B build -DLT_LLVM_INSTALL_DIR=/usr/lib/llvm-17 -DCMAKE_BUILD_TYPE=release && \
    cmake --build build -j $(nproc)

FROM python:3.11-slim-bookworm as perceptor

ENV PYTHONFAULTHANDLER=1 \
    PYTHONHASHSEED=random \
    PYTHONUNBUFFERED=1

WORKDIR /app

ENV PIP_DEFAULT_TIMEOUT=100 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    POETRY_VERSION=1.6.1

RUN apt-get update && apt-get install -y \
  git \
  gcc \
  make \
  cmake \
  && rm -rf /var/lib/apt/lists/*

RUN pip install "poetry==$POETRY_VERSION"
RUN python -m venv /venv

COPY pyproject.toml poetry.lock ./
RUN poetry export --without-hashes -f requirements.txt | /venv/bin/pip install -r /dev/stdin

COPY . .
RUN poetry build && /venv/bin/pip install dist/*.whl

FROM debian:bookworm as donut

RUN apt-get update
RUN apt-get install --no-install-recommends --no-install-suggests -y \
      mingw-w64 zip build-essential perl python3 xml2 pkg-config automake \
      libtool autotools-dev make g++ git ruby wget libssl-dev

WORKDIR /app
RUN git clone https://github.com/TheWover/donut.git
WORKDIR /app/donut
RUN make -f Makefile

FROM base as final

RUN apt-get update && apt-get install -y \
  imagemagick \
  && rm -rf /var/lib/apt/lists/*

COPY --from=ssage /app/SsagePass/Obfuscation/build/libSsageObfuscator.so /opt/libSsageObfuscator.so
COPY --from=donut /app/donut/donut /opt/donut
COPY --from=perceptor /venv /venv
COPY config.docker.yaml config.yaml

RUN ln -s /usr/bin/python3 /usr/local/bin/python

RUN apt-get update && apt-get install -y \
  git \
  mingw-w64 \
  osslsigncode \
  libmono-cecil-cil \
  && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/tpoechtrager/wclang && \
    cmake -S wclang -B ./wclang/build && \
    cd wclang/build && \
    make && make install && \
    cd /app && rm -rf wclang

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh && \
  mkdir tmp

ENTRYPOINT ["/entrypoint.sh"]
