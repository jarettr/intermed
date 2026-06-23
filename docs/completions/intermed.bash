_intermed() {
    local i cur prev opts cmd
    COMPREPLY=()
    if [[ "${BASH_VERSINFO[0]}" -ge 4 ]]; then
        cur="$2"
    else
        cur="${COMP_WORDS[COMP_CWORD]}"
    fi
    prev="$3"
    cmd=""
    opts=""

    for i in "${COMP_WORDS[@]:0:COMP_CWORD}"
    do
        case "${cmd},${i}" in
            ",$1")
                cmd="intermed"
                ;;
            intermed,cache)
                cmd="intermed__subcmd__cache"
                ;;
            intermed,db)
                cmd="intermed__subcmd__db"
                ;;
            intermed,demo)
                cmd="intermed__subcmd__demo"
                ;;
            intermed,deps)
                cmd="intermed__subcmd__deps"
                ;;
            intermed,doctor)
                cmd="intermed__subcmd__doctor"
                ;;
            intermed,help)
                cmd="intermed__subcmd__help"
                ;;
            intermed,history)
                cmd="intermed__subcmd__history"
                ;;
            intermed,impact)
                cmd="intermed__subcmd__impact"
                ;;
            intermed,lab)
                cmd="intermed__subcmd__lab"
                ;;
            intermed,mixin-map)
                cmd="intermed__subcmd__mixin__subcmd__map"
                ;;
            intermed,rules)
                cmd="intermed__subcmd__rules"
                ;;
            intermed,sbom)
                cmd="intermed__subcmd__sbom"
                ;;
            intermed,spark-map)
                cmd="intermed__subcmd__spark__subcmd__map"
                ;;
            intermed,trends)
                cmd="intermed__subcmd__trends"
                ;;
            intermed,vfs)
                cmd="intermed__subcmd__vfs"
                ;;
            intermed__subcmd__cache,clear)
                cmd="intermed__subcmd__cache__subcmd__clear"
                ;;
            intermed__subcmd__cache,help)
                cmd="intermed__subcmd__cache__subcmd__help"
                ;;
            intermed__subcmd__cache,prune)
                cmd="intermed__subcmd__cache__subcmd__prune"
                ;;
            intermed__subcmd__cache,stats)
                cmd="intermed__subcmd__cache__subcmd__stats"
                ;;
            intermed__subcmd__cache__subcmd__help,clear)
                cmd="intermed__subcmd__cache__subcmd__help__subcmd__clear"
                ;;
            intermed__subcmd__cache__subcmd__help,help)
                cmd="intermed__subcmd__cache__subcmd__help__subcmd__help"
                ;;
            intermed__subcmd__cache__subcmd__help,prune)
                cmd="intermed__subcmd__cache__subcmd__help__subcmd__prune"
                ;;
            intermed__subcmd__cache__subcmd__help,stats)
                cmd="intermed__subcmd__cache__subcmd__help__subcmd__stats"
                ;;
            intermed__subcmd__db,help)
                cmd="intermed__subcmd__db__subcmd__help"
                ;;
            intermed__subcmd__db,query)
                cmd="intermed__subcmd__db__subcmd__query"
                ;;
            intermed__subcmd__db__subcmd__help,help)
                cmd="intermed__subcmd__db__subcmd__help__subcmd__help"
                ;;
            intermed__subcmd__db__subcmd__help,query)
                cmd="intermed__subcmd__db__subcmd__help__subcmd__query"
                ;;
            intermed__subcmd__demo,help)
                cmd="intermed__subcmd__demo__subcmd__help"
                ;;
            intermed__subcmd__demo,report)
                cmd="intermed__subcmd__demo__subcmd__report"
                ;;
            intermed__subcmd__demo__subcmd__help,help)
                cmd="intermed__subcmd__demo__subcmd__help__subcmd__help"
                ;;
            intermed__subcmd__demo__subcmd__help,report)
                cmd="intermed__subcmd__demo__subcmd__help__subcmd__report"
                ;;
            intermed__subcmd__deps,graph)
                cmd="intermed__subcmd__deps__subcmd__graph"
                ;;
            intermed__subcmd__deps,help)
                cmd="intermed__subcmd__deps__subcmd__help"
                ;;
            intermed__subcmd__deps,implicit)
                cmd="intermed__subcmd__deps__subcmd__implicit"
                ;;
            intermed__subcmd__deps,path)
                cmd="intermed__subcmd__deps__subcmd__path"
                ;;
            intermed__subcmd__deps,resolve)
                cmd="intermed__subcmd__deps__subcmd__resolve"
                ;;
            intermed__subcmd__deps,why)
                cmd="intermed__subcmd__deps__subcmd__why"
                ;;
            intermed__subcmd__deps,why-missing)
                cmd="intermed__subcmd__deps__subcmd__why__subcmd__missing"
                ;;
            intermed__subcmd__deps__subcmd__help,graph)
                cmd="intermed__subcmd__deps__subcmd__help__subcmd__graph"
                ;;
            intermed__subcmd__deps__subcmd__help,help)
                cmd="intermed__subcmd__deps__subcmd__help__subcmd__help"
                ;;
            intermed__subcmd__deps__subcmd__help,implicit)
                cmd="intermed__subcmd__deps__subcmd__help__subcmd__implicit"
                ;;
            intermed__subcmd__deps__subcmd__help,path)
                cmd="intermed__subcmd__deps__subcmd__help__subcmd__path"
                ;;
            intermed__subcmd__deps__subcmd__help,resolve)
                cmd="intermed__subcmd__deps__subcmd__help__subcmd__resolve"
                ;;
            intermed__subcmd__deps__subcmd__help,why)
                cmd="intermed__subcmd__deps__subcmd__help__subcmd__why"
                ;;
            intermed__subcmd__deps__subcmd__help,why-missing)
                cmd="intermed__subcmd__deps__subcmd__help__subcmd__why__subcmd__missing"
                ;;
            intermed__subcmd__help,cache)
                cmd="intermed__subcmd__help__subcmd__cache"
                ;;
            intermed__subcmd__help,db)
                cmd="intermed__subcmd__help__subcmd__db"
                ;;
            intermed__subcmd__help,demo)
                cmd="intermed__subcmd__help__subcmd__demo"
                ;;
            intermed__subcmd__help,deps)
                cmd="intermed__subcmd__help__subcmd__deps"
                ;;
            intermed__subcmd__help,doctor)
                cmd="intermed__subcmd__help__subcmd__doctor"
                ;;
            intermed__subcmd__help,help)
                cmd="intermed__subcmd__help__subcmd__help"
                ;;
            intermed__subcmd__help,history)
                cmd="intermed__subcmd__help__subcmd__history"
                ;;
            intermed__subcmd__help,impact)
                cmd="intermed__subcmd__help__subcmd__impact"
                ;;
            intermed__subcmd__help,lab)
                cmd="intermed__subcmd__help__subcmd__lab"
                ;;
            intermed__subcmd__help,mixin-map)
                cmd="intermed__subcmd__help__subcmd__mixin__subcmd__map"
                ;;
            intermed__subcmd__help,rules)
                cmd="intermed__subcmd__help__subcmd__rules"
                ;;
            intermed__subcmd__help,sbom)
                cmd="intermed__subcmd__help__subcmd__sbom"
                ;;
            intermed__subcmd__help,spark-map)
                cmd="intermed__subcmd__help__subcmd__spark__subcmd__map"
                ;;
            intermed__subcmd__help,trends)
                cmd="intermed__subcmd__help__subcmd__trends"
                ;;
            intermed__subcmd__help,vfs)
                cmd="intermed__subcmd__help__subcmd__vfs"
                ;;
            intermed__subcmd__help__subcmd__cache,clear)
                cmd="intermed__subcmd__help__subcmd__cache__subcmd__clear"
                ;;
            intermed__subcmd__help__subcmd__cache,prune)
                cmd="intermed__subcmd__help__subcmd__cache__subcmd__prune"
                ;;
            intermed__subcmd__help__subcmd__cache,stats)
                cmd="intermed__subcmd__help__subcmd__cache__subcmd__stats"
                ;;
            intermed__subcmd__help__subcmd__db,query)
                cmd="intermed__subcmd__help__subcmd__db__subcmd__query"
                ;;
            intermed__subcmd__help__subcmd__demo,report)
                cmd="intermed__subcmd__help__subcmd__demo__subcmd__report"
                ;;
            intermed__subcmd__help__subcmd__deps,graph)
                cmd="intermed__subcmd__help__subcmd__deps__subcmd__graph"
                ;;
            intermed__subcmd__help__subcmd__deps,implicit)
                cmd="intermed__subcmd__help__subcmd__deps__subcmd__implicit"
                ;;
            intermed__subcmd__help__subcmd__deps,path)
                cmd="intermed__subcmd__help__subcmd__deps__subcmd__path"
                ;;
            intermed__subcmd__help__subcmd__deps,resolve)
                cmd="intermed__subcmd__help__subcmd__deps__subcmd__resolve"
                ;;
            intermed__subcmd__help__subcmd__deps,why)
                cmd="intermed__subcmd__help__subcmd__deps__subcmd__why"
                ;;
            intermed__subcmd__help__subcmd__deps,why-missing)
                cmd="intermed__subcmd__help__subcmd__deps__subcmd__why__subcmd__missing"
                ;;
            intermed__subcmd__help__subcmd__history,conflicts)
                cmd="intermed__subcmd__help__subcmd__history__subcmd__conflicts"
                ;;
            intermed__subcmd__help__subcmd__history,diff)
                cmd="intermed__subcmd__help__subcmd__history__subcmd__diff"
                ;;
            intermed__subcmd__help__subcmd__history,patterns)
                cmd="intermed__subcmd__help__subcmd__history__subcmd__patterns"
                ;;
            intermed__subcmd__help__subcmd__history,prune)
                cmd="intermed__subcmd__help__subcmd__history__subcmd__prune"
                ;;
            intermed__subcmd__help__subcmd__impact,remove)
                cmd="intermed__subcmd__help__subcmd__impact__subcmd__remove"
                ;;
            intermed__subcmd__help__subcmd__impact,update)
                cmd="intermed__subcmd__help__subcmd__impact__subcmd__update"
                ;;
            intermed__subcmd__help__subcmd__lab,discover)
                cmd="intermed__subcmd__help__subcmd__lab__subcmd__discover"
                ;;
            intermed__subcmd__help__subcmd__lab,eval)
                cmd="intermed__subcmd__help__subcmd__lab__subcmd__eval"
                ;;
            intermed__subcmd__help__subcmd__lab,report)
                cmd="intermed__subcmd__help__subcmd__lab__subcmd__report"
                ;;
            intermed__subcmd__help__subcmd__lab,run)
                cmd="intermed__subcmd__help__subcmd__lab__subcmd__run"
                ;;
            intermed__subcmd__help__subcmd__rules,check)
                cmd="intermed__subcmd__help__subcmd__rules__subcmd__check"
                ;;
            intermed__subcmd__help__subcmd__rules,explain)
                cmd="intermed__subcmd__help__subcmd__rules__subcmd__explain"
                ;;
            intermed__subcmd__help__subcmd__rules,generate)
                cmd="intermed__subcmd__help__subcmd__rules__subcmd__generate"
                ;;
            intermed__subcmd__help__subcmd__rules,install)
                cmd="intermed__subcmd__help__subcmd__rules__subcmd__install"
                ;;
            intermed__subcmd__help__subcmd__rules,registry)
                cmd="intermed__subcmd__help__subcmd__rules__subcmd__registry"
                ;;
            intermed__subcmd__help__subcmd__rules,sign)
                cmd="intermed__subcmd__help__subcmd__rules__subcmd__sign"
                ;;
            intermed__subcmd__help__subcmd__rules,update)
                cmd="intermed__subcmd__help__subcmd__rules__subcmd__update"
                ;;
            intermed__subcmd__help__subcmd__rules,verify)
                cmd="intermed__subcmd__help__subcmd__rules__subcmd__verify"
                ;;
            intermed__subcmd__help__subcmd__sbom,export)
                cmd="intermed__subcmd__help__subcmd__sbom__subcmd__export"
                ;;
            intermed__subcmd__help__subcmd__trends,mixin-overlaps)
                cmd="intermed__subcmd__help__subcmd__trends__subcmd__mixin__subcmd__overlaps"
                ;;
            intermed__subcmd__help__subcmd__trends,mixin-risk)
                cmd="intermed__subcmd__help__subcmd__trends__subcmd__mixin__subcmd__risk"
                ;;
            intermed__subcmd__help__subcmd__vfs,explain)
                cmd="intermed__subcmd__help__subcmd__vfs__subcmd__explain"
                ;;
            intermed__subcmd__help__subcmd__vfs,overlay)
                cmd="intermed__subcmd__help__subcmd__vfs__subcmd__overlay"
                ;;
            intermed__subcmd__help__subcmd__vfs,scan)
                cmd="intermed__subcmd__help__subcmd__vfs__subcmd__scan"
                ;;
            intermed__subcmd__history,conflicts)
                cmd="intermed__subcmd__history__subcmd__conflicts"
                ;;
            intermed__subcmd__history,diff)
                cmd="intermed__subcmd__history__subcmd__diff"
                ;;
            intermed__subcmd__history,help)
                cmd="intermed__subcmd__history__subcmd__help"
                ;;
            intermed__subcmd__history,patterns)
                cmd="intermed__subcmd__history__subcmd__patterns"
                ;;
            intermed__subcmd__history,prune)
                cmd="intermed__subcmd__history__subcmd__prune"
                ;;
            intermed__subcmd__history__subcmd__help,conflicts)
                cmd="intermed__subcmd__history__subcmd__help__subcmd__conflicts"
                ;;
            intermed__subcmd__history__subcmd__help,diff)
                cmd="intermed__subcmd__history__subcmd__help__subcmd__diff"
                ;;
            intermed__subcmd__history__subcmd__help,help)
                cmd="intermed__subcmd__history__subcmd__help__subcmd__help"
                ;;
            intermed__subcmd__history__subcmd__help,patterns)
                cmd="intermed__subcmd__history__subcmd__help__subcmd__patterns"
                ;;
            intermed__subcmd__history__subcmd__help,prune)
                cmd="intermed__subcmd__history__subcmd__help__subcmd__prune"
                ;;
            intermed__subcmd__impact,help)
                cmd="intermed__subcmd__impact__subcmd__help"
                ;;
            intermed__subcmd__impact,remove)
                cmd="intermed__subcmd__impact__subcmd__remove"
                ;;
            intermed__subcmd__impact,update)
                cmd="intermed__subcmd__impact__subcmd__update"
                ;;
            intermed__subcmd__impact__subcmd__help,help)
                cmd="intermed__subcmd__impact__subcmd__help__subcmd__help"
                ;;
            intermed__subcmd__impact__subcmd__help,remove)
                cmd="intermed__subcmd__impact__subcmd__help__subcmd__remove"
                ;;
            intermed__subcmd__impact__subcmd__help,update)
                cmd="intermed__subcmd__impact__subcmd__help__subcmd__update"
                ;;
            intermed__subcmd__lab,discover)
                cmd="intermed__subcmd__lab__subcmd__discover"
                ;;
            intermed__subcmd__lab,eval)
                cmd="intermed__subcmd__lab__subcmd__eval"
                ;;
            intermed__subcmd__lab,help)
                cmd="intermed__subcmd__lab__subcmd__help"
                ;;
            intermed__subcmd__lab,report)
                cmd="intermed__subcmd__lab__subcmd__report"
                ;;
            intermed__subcmd__lab,run)
                cmd="intermed__subcmd__lab__subcmd__run"
                ;;
            intermed__subcmd__lab__subcmd__help,discover)
                cmd="intermed__subcmd__lab__subcmd__help__subcmd__discover"
                ;;
            intermed__subcmd__lab__subcmd__help,eval)
                cmd="intermed__subcmd__lab__subcmd__help__subcmd__eval"
                ;;
            intermed__subcmd__lab__subcmd__help,help)
                cmd="intermed__subcmd__lab__subcmd__help__subcmd__help"
                ;;
            intermed__subcmd__lab__subcmd__help,report)
                cmd="intermed__subcmd__lab__subcmd__help__subcmd__report"
                ;;
            intermed__subcmd__lab__subcmd__help,run)
                cmd="intermed__subcmd__lab__subcmd__help__subcmd__run"
                ;;
            intermed__subcmd__rules,check)
                cmd="intermed__subcmd__rules__subcmd__check"
                ;;
            intermed__subcmd__rules,explain)
                cmd="intermed__subcmd__rules__subcmd__explain"
                ;;
            intermed__subcmd__rules,generate)
                cmd="intermed__subcmd__rules__subcmd__generate"
                ;;
            intermed__subcmd__rules,help)
                cmd="intermed__subcmd__rules__subcmd__help"
                ;;
            intermed__subcmd__rules,install)
                cmd="intermed__subcmd__rules__subcmd__install"
                ;;
            intermed__subcmd__rules,registry)
                cmd="intermed__subcmd__rules__subcmd__registry"
                ;;
            intermed__subcmd__rules,sign)
                cmd="intermed__subcmd__rules__subcmd__sign"
                ;;
            intermed__subcmd__rules,update)
                cmd="intermed__subcmd__rules__subcmd__update"
                ;;
            intermed__subcmd__rules,verify)
                cmd="intermed__subcmd__rules__subcmd__verify"
                ;;
            intermed__subcmd__rules__subcmd__help,check)
                cmd="intermed__subcmd__rules__subcmd__help__subcmd__check"
                ;;
            intermed__subcmd__rules__subcmd__help,explain)
                cmd="intermed__subcmd__rules__subcmd__help__subcmd__explain"
                ;;
            intermed__subcmd__rules__subcmd__help,generate)
                cmd="intermed__subcmd__rules__subcmd__help__subcmd__generate"
                ;;
            intermed__subcmd__rules__subcmd__help,help)
                cmd="intermed__subcmd__rules__subcmd__help__subcmd__help"
                ;;
            intermed__subcmd__rules__subcmd__help,install)
                cmd="intermed__subcmd__rules__subcmd__help__subcmd__install"
                ;;
            intermed__subcmd__rules__subcmd__help,registry)
                cmd="intermed__subcmd__rules__subcmd__help__subcmd__registry"
                ;;
            intermed__subcmd__rules__subcmd__help,sign)
                cmd="intermed__subcmd__rules__subcmd__help__subcmd__sign"
                ;;
            intermed__subcmd__rules__subcmd__help,update)
                cmd="intermed__subcmd__rules__subcmd__help__subcmd__update"
                ;;
            intermed__subcmd__rules__subcmd__help,verify)
                cmd="intermed__subcmd__rules__subcmd__help__subcmd__verify"
                ;;
            intermed__subcmd__sbom,export)
                cmd="intermed__subcmd__sbom__subcmd__export"
                ;;
            intermed__subcmd__sbom,help)
                cmd="intermed__subcmd__sbom__subcmd__help"
                ;;
            intermed__subcmd__sbom__subcmd__help,export)
                cmd="intermed__subcmd__sbom__subcmd__help__subcmd__export"
                ;;
            intermed__subcmd__sbom__subcmd__help,help)
                cmd="intermed__subcmd__sbom__subcmd__help__subcmd__help"
                ;;
            intermed__subcmd__trends,help)
                cmd="intermed__subcmd__trends__subcmd__help"
                ;;
            intermed__subcmd__trends,mixin-overlaps)
                cmd="intermed__subcmd__trends__subcmd__mixin__subcmd__overlaps"
                ;;
            intermed__subcmd__trends,mixin-risk)
                cmd="intermed__subcmd__trends__subcmd__mixin__subcmd__risk"
                ;;
            intermed__subcmd__trends__subcmd__help,help)
                cmd="intermed__subcmd__trends__subcmd__help__subcmd__help"
                ;;
            intermed__subcmd__trends__subcmd__help,mixin-overlaps)
                cmd="intermed__subcmd__trends__subcmd__help__subcmd__mixin__subcmd__overlaps"
                ;;
            intermed__subcmd__trends__subcmd__help,mixin-risk)
                cmd="intermed__subcmd__trends__subcmd__help__subcmd__mixin__subcmd__risk"
                ;;
            intermed__subcmd__vfs,explain)
                cmd="intermed__subcmd__vfs__subcmd__explain"
                ;;
            intermed__subcmd__vfs,help)
                cmd="intermed__subcmd__vfs__subcmd__help"
                ;;
            intermed__subcmd__vfs,overlay)
                cmd="intermed__subcmd__vfs__subcmd__overlay"
                ;;
            intermed__subcmd__vfs,scan)
                cmd="intermed__subcmd__vfs__subcmd__scan"
                ;;
            intermed__subcmd__vfs__subcmd__help,explain)
                cmd="intermed__subcmd__vfs__subcmd__help__subcmd__explain"
                ;;
            intermed__subcmd__vfs__subcmd__help,help)
                cmd="intermed__subcmd__vfs__subcmd__help__subcmd__help"
                ;;
            intermed__subcmd__vfs__subcmd__help,overlay)
                cmd="intermed__subcmd__vfs__subcmd__help__subcmd__overlay"
                ;;
            intermed__subcmd__vfs__subcmd__help,scan)
                cmd="intermed__subcmd__vfs__subcmd__help__subcmd__scan"
                ;;
            *)
                ;;
        esac
    done

    case "${cmd}" in
        intermed)
            opts="-v -h -V --config --dump-config --quiet --verbose --help --version doctor vfs deps impact mixin-map spark-map lab rules db history trends cache sbom demo help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 1 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__cache)
            opts="-v -h --config --dump-config --quiet --verbose --help stats prune clear help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__cache__subcmd__clear)
            opts="-v -h --cache-dir --config --dump-config --quiet --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cache-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__cache__subcmd__help)
            opts="stats prune clear help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__cache__subcmd__help__subcmd__clear)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__cache__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__cache__subcmd__help__subcmd__prune)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__cache__subcmd__help__subcmd__stats)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__cache__subcmd__prune)
            opts="-v -h --cache-dir --config --dump-config --quiet --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cache-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__cache__subcmd__stats)
            opts="-v -h --cache-dir --config --dump-config --quiet --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cache-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__db)
            opts="-v -h --config --dump-config --quiet --verbose --help query help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__db__subcmd__help)
            opts="query help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__db__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__db__subcmd__help__subcmd__query)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__db__subcmd__query)
            opts="-v -h --db --config --dump-config --quiet --verbose --help <SQL>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --db)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__demo)
            opts="-v -h --config --dump-config --quiet --verbose --help report help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__demo__subcmd__help)
            opts="report help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__demo__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__demo__subcmd__help__subcmd__report)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__demo__subcmd__report)
            opts="-o -v -h --out --config --dump-config --quiet --verbose --help <RUN_DIR>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --out)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -o)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__deps)
            opts="-v -h --config --dump-config --quiet --verbose --help graph resolve why why-missing implicit path help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__deps__subcmd__graph)
            opts="-v -h --mods-dir --config --dump-config --quiet --verbose --help [TARGET]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --mods-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__deps__subcmd__help)
            opts="graph resolve why why-missing implicit path help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__deps__subcmd__help__subcmd__graph)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__deps__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__deps__subcmd__help__subcmd__implicit)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__deps__subcmd__help__subcmd__path)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__deps__subcmd__help__subcmd__resolve)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__deps__subcmd__help__subcmd__why)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__deps__subcmd__help__subcmd__why__subcmd__missing)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__deps__subcmd__implicit)
            opts="-v -h --namespace --mods-dir --json --config --dump-config --quiet --verbose --help [TARGET]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --namespace)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mods-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__deps__subcmd__path)
            opts="-v -h --mods-dir --json --config --dump-config --quiet --verbose --help <FROM> <TO> [TARGET]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --mods-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__deps__subcmd__resolve)
            opts="-v -h --mods-dir --config --dump-config --quiet --verbose --help [TARGET]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --mods-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__deps__subcmd__why)
            opts="-v -h --mods-dir --json --config --dump-config --quiet --verbose --help <ID> [TARGET]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --mods-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__deps__subcmd__why__subcmd__missing)
            opts="-v -h --mods-dir --json --config --dump-config --quiet --verbose --help <ID> [TARGET]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --mods-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__doctor)
            opts="-v -h --mods-dir --mixin-risk --logic --threads --jobs --json --sarif --html --no-color --profile --exit-zero --no-cache --cache-dir --cache-remote-dir --cache-max-size --cache-max-age-days --changed-since --dump-facts --explain --performance --spark-report --perf-tick-spike-ms --perf-high-cpu-percent --perf-hot-method-floor --perf-tick-spike-warn-ms --metadata-level --resource-level --security-min-note-signals --sbom-well-identified-trust --log-parallel-line-threshold --security-corroborated-confidence --minecraft-jar --minecraft-mappings --mixin-level --no-mixin-handler-effects --mixin-handler-effects --no-mixin-recommendations --mixin-recommendations --db --db-best-effort --rule-pack --rule-pack-dir --core-rule-pack-only --rule-pack-trusted-keys --rule-pack-registry --allow-insecure-registry --allow-unsigned-rules --config --dump-config --quiet --verbose --help [TARGET]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --mods-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --logic)
                    COMPREPLY=($(compgen -W "columnar souffle duckdb" -- "${cur}"))
                    return 0
                    ;;
                --jobs)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --threads)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --html)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cache-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cache-remote-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cache-max-size)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cache-max-age-days)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --changed-since)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --dump-facts)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --explain)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --spark-report)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --perf-tick-spike-ms)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --perf-high-cpu-percent)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --perf-hot-method-floor)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --perf-tick-spike-warn-ms)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --metadata-level)
                    COMPREPLY=($(compgen -W "basic enriched full" -- "${cur}"))
                    return 0
                    ;;
                --resource-level)
                    COMPREPLY=($(compgen -W "basic semantic full" -- "${cur}"))
                    return 0
                    ;;
                --security-min-note-signals)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sbom-well-identified-trust)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --log-parallel-line-threshold)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --security-corroborated-confidence)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --minecraft-jar)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --minecraft-mappings)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mixin-level)
                    COMPREPLY=($(compgen -W "normal detailed full" -- "${cur}"))
                    return 0
                    ;;
                --db)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rule-pack)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rule-pack-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rule-pack-trusted-keys)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rule-pack-registry)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help)
            opts="doctor vfs deps impact mixin-map spark-map lab rules db history trends cache sbom demo help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__cache)
            opts="stats prune clear"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__cache__subcmd__clear)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__cache__subcmd__prune)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__cache__subcmd__stats)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__db)
            opts="query"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__db__subcmd__query)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__demo)
            opts="report"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__demo__subcmd__report)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__deps)
            opts="graph resolve why why-missing implicit path"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__deps__subcmd__graph)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__deps__subcmd__implicit)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__deps__subcmd__path)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__deps__subcmd__resolve)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__deps__subcmd__why)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__deps__subcmd__why__subcmd__missing)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__doctor)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__history)
            opts="conflicts patterns diff prune"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__history__subcmd__conflicts)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__history__subcmd__diff)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__history__subcmd__patterns)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__history__subcmd__prune)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__impact)
            opts="remove update"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__impact__subcmd__remove)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__impact__subcmd__update)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__lab)
            opts="discover run report eval"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__lab__subcmd__discover)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__lab__subcmd__eval)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__lab__subcmd__report)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__lab__subcmd__run)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__mixin__subcmd__map)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__rules)
            opts="check generate sign verify update registry install explain"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__rules__subcmd__check)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__rules__subcmd__explain)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__rules__subcmd__generate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__rules__subcmd__install)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__rules__subcmd__registry)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__rules__subcmd__sign)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__rules__subcmd__update)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__rules__subcmd__verify)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__sbom)
            opts="export"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__sbom__subcmd__export)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__spark__subcmd__map)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__trends)
            opts="mixin-risk mixin-overlaps"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__trends__subcmd__mixin__subcmd__overlaps)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__trends__subcmd__mixin__subcmd__risk)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__vfs)
            opts="scan explain overlay"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__vfs__subcmd__explain)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__vfs__subcmd__overlay)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__help__subcmd__vfs__subcmd__scan)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__history)
            opts="-v -h --config --dump-config --quiet --verbose --help conflicts patterns diff prune help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__history__subcmd__conflicts)
            opts="-v -h --db --since --config --dump-config --quiet --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --db)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --since)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__history__subcmd__diff)
            opts="-v -h --db --run-a --run-b --json --config --dump-config --quiet --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --db)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --run-a)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --run-b)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__history__subcmd__help)
            opts="conflicts patterns diff prune help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__history__subcmd__help__subcmd__conflicts)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__history__subcmd__help__subcmd__diff)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__history__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__history__subcmd__help__subcmd__patterns)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__history__subcmd__help__subcmd__prune)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__history__subcmd__patterns)
            opts="-v -h --db --limit --config --dump-config --quiet --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --db)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --limit)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__history__subcmd__prune)
            opts="-v -h --db --keep --config --dump-config --quiet --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --db)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keep)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__impact)
            opts="-v -h --config --dump-config --quiet --verbose --help remove update help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__impact__subcmd__help)
            opts="remove update help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__impact__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__impact__subcmd__help__subcmd__remove)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__impact__subcmd__help__subcmd__update)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__impact__subcmd__remove)
            opts="-v -h --mods-dir --json --config --dump-config --quiet --verbose --help <ID> [TARGET]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --mods-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__impact__subcmd__update)
            opts="-v -h --mods-dir --json --config --dump-config --quiet --verbose --help <ID> <FROM> <TO> [TARGET]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --mods-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__lab)
            opts="-v -h --config --dump-config --quiet --verbose --help discover run report eval help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__lab__subcmd__discover)
            opts="-v -h --out --config --dump-config --quiet --verbose --help <CANDIDATES>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --out)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__lab__subcmd__eval)
            opts="-v -h --manifest --report --run --min-severity --out --config --dump-config --quiet --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --manifest)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --report)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --run)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --min-severity)
                    COMPREPLY=($(compgen -W "note warn error" -- "${cur}"))
                    return 0
                    ;;
                --out)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__lab__subcmd__help)
            opts="discover run report eval help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__lab__subcmd__help__subcmd__discover)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__lab__subcmd__help__subcmd__eval)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__lab__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__lab__subcmd__help__subcmd__report)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__lab__subcmd__help__subcmd__run)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__lab__subcmd__report)
            opts="-v -h --out --config --dump-config --quiet --verbose --help <RUN>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --out)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__lab__subcmd__run)
            opts="-v -h --logs --out --lab-excerpt-max --config --dump-config --quiet --verbose --help <LOCK>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --logs)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --out)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --lab-excerpt-max)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__mixin__subcmd__map)
            opts="-v -h --graph-format --graph-out --no-color --config --dump-config --quiet --verbose --help [TARGET]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --graph-format)
                    COMPREPLY=($(compgen -W "json graph-json dot graphml html" -- "${cur}"))
                    return 0
                    ;;
                --graph-out)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__rules)
            opts="-v -h --config --dump-config --quiet --verbose --help check generate sign verify update registry install explain help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__rules__subcmd__check)
            opts="-v -h --require-signature --trusted-keys --trace --facts --config --dump-config --quiet --verbose --help [PATH]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --trusted-keys)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --facts)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__rules__subcmd__explain)
            opts="-v -h --rule --facts --config --dump-config --quiet --verbose --help [PACK]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --rule)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --facts)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__rules__subcmd__generate)
            opts="-v -h --backend --out --config --dump-config --quiet --verbose --help [PACK]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --backend)
                    COMPREPLY=($(compgen -W "sql rust datalog explain" -- "${cur}"))
                    return 0
                    ;;
                --out)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__rules__subcmd__help)
            opts="check generate sign verify update registry install explain help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__rules__subcmd__help__subcmd__check)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__rules__subcmd__help__subcmd__explain)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__rules__subcmd__help__subcmd__generate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__rules__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__rules__subcmd__help__subcmd__install)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__rules__subcmd__help__subcmd__registry)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__rules__subcmd__help__subcmd__sign)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__rules__subcmd__help__subcmd__update)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__rules__subcmd__help__subcmd__verify)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__rules__subcmd__install)
            opts="-v -h --registry --pack --install-dir --trusted-keys --allow-insecure-registry --allow-unsigned-rules --config --dump-config --quiet --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --registry)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pack)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --install-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trusted-keys)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__rules__subcmd__registry)
            opts="-v -h --registry --allow-insecure-registry --config --dump-config --quiet --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --registry)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__rules__subcmd__sign)
            opts="-v -h --key --out --config --dump-config --quiet --verbose --help <PACK>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --out)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__rules__subcmd__update)
            opts="-v -h --registry --pack --install-dir --trusted-keys --allow-insecure-registry --allow-unsigned-rules --config --dump-config --quiet --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --registry)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pack)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --install-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trusted-keys)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__rules__subcmd__verify)
            opts="-v -h --trusted-keys --config --dump-config --quiet --verbose --help <PACK>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --trusted-keys)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__sbom)
            opts="-v -h --config --dump-config --quiet --verbose --help export help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__sbom__subcmd__export)
            opts="-v -h --mods-dir --format --out --config --dump-config --quiet --verbose --help [TARGET]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --mods-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "spdx-json cyclonedx-json" -- "${cur}"))
                    return 0
                    ;;
                --out)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__sbom__subcmd__help)
            opts="export help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__sbom__subcmd__help__subcmd__export)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__sbom__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__spark__subcmd__map)
            opts="-v -h --spark-report --no-color --config --dump-config --quiet --verbose --help [TARGET]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --spark-report)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__trends)
            opts="-v -h --config --dump-config --quiet --verbose --help mixin-risk mixin-overlaps help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__trends__subcmd__help)
            opts="mixin-risk mixin-overlaps help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__trends__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__trends__subcmd__help__subcmd__mixin__subcmd__overlaps)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__trends__subcmd__help__subcmd__mixin__subcmd__risk)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__trends__subcmd__mixin__subcmd__overlaps)
            opts="-v -h --db --limit --config --dump-config --quiet --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --db)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --limit)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__trends__subcmd__mixin__subcmd__risk)
            opts="-v -h --db --config --dump-config --quiet --verbose --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --db)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__vfs)
            opts="-v -h --config --dump-config --quiet --verbose --help scan explain overlay help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__vfs__subcmd__explain)
            opts="-v -h --path --ast --resource-level --no-color --config --dump-config --quiet --verbose --help [TARGET]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --path)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --resource-level)
                    COMPREPLY=($(compgen -W "basic semantic full" -- "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__vfs__subcmd__help)
            opts="scan explain overlay help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__vfs__subcmd__help__subcmd__explain)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__vfs__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__vfs__subcmd__help__subcmd__overlay)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__vfs__subcmd__help__subcmd__scan)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__vfs__subcmd__overlay)
            opts="-v -h --out --include-unsafe-winners --explain-plan --no-color --config --dump-config --quiet --verbose --help [TARGET]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --out)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        intermed__subcmd__vfs__subcmd__scan)
            opts="-v -h --path --ast --resource-level --no-color --config --dump-config --quiet --verbose --help [TARGET]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --path)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --resource-level)
                    COMPREPLY=($(compgen -W "basic semantic full" -- "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
    esac
}

if [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -ge 4 || "${BASH_VERSINFO[0]}" -gt 4 ]]; then
    complete -F _intermed -o nosort -o bashdefault -o default intermed
else
    complete -F _intermed -o bashdefault -o default intermed
fi
