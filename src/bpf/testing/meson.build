# tracing_sources are compatible with kernel v6.3+
#
# These files do not require features only available
# in the newer struct_ops approach and are thus compatible
# for both approaches.
tracing_sources = [
    '0010-Microdia__Aula-Mini60-HE.bpf.c',
    '0010-Gaomon__M6.bpf.c',
    '0010-XPPen__DecoProV1.bpf.c',
    '0040-XPPen__ArtistPro16Gen2.bpf.c',
    '0010-Iiyama__ProLite-TE9804MIS.bpf.c',
    '0010-XPPen__DecoSE.bpf.c',
]

# 'sources' are BPF programs only compatible with
# struct_ops (kernel v6.11+)
sources = [
]

foreach bpf: tracing_sources
    bpf_sources += [
        {
            'name': bpf,
            'section': 'testing',
            'file': files(bpf)[0],
            'install': install_testing,
            'build_by_default': install_testing,
            'compile_with_tracing': false,
        },
    ]
    if use_bpf_tracing
        bpf_sources += [
            {
                'name': bpf,
                'section': 'testing',
                'file': files(bpf)[0],
                'install': install_testing,
                'build_by_default': install_testing,
                'compile_with_tracing': true,
            },
        ]
    endif
endforeach

foreach bpf: sources
    bpf_sources += [
        {
            'name': bpf,
            'section': 'testing',
            'file': files(bpf)[0],
            'install': install_testing,
            'build_by_default': install_testing,
            'compile_with_tracing': false,
        },
    ]
endforeach
