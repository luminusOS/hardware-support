set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

test:
    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s extensions/nvidia-open/tests

check:
    for script in extensions/nvidia-open/bin/*.sh; do bash -n "$script"; done

build-nvidia archive scratch:
    bash extensions/nvidia-open/bin/build-candidate.sh {{quote(archive)}} {{quote(scratch)}}

build-nvidia-modules source kernel_devel scratch:
    bash extensions/nvidia-open/bin/build-modules.sh {{quote(source)}} {{quote(kernel_devel)}} {{quote(scratch)}}
