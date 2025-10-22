FROM mambaorg/micromamba:1.5.8

COPY environment.yml /tmp/env.yml
RUN micromamba env create -y -n base -f /tmp/env.yml && \
    micromamba clean --all --yes

COPY ip_enrich.py /opt/ip_enrich/
WORKDIR /opt/ip_enrich

# ENTRYPOINT automatically set by micromamba
