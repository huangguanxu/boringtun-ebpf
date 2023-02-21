#!/bin/bash

if [ "$#" -eq 0 ]; then
    echo "Usage: [options]"
    echo "--cpu <str>             Bind irqs to these CPUs, by default is all core."
    exit 3
fi

input_cpu=""
thread=""
peer=""

for var in "$@"; do
    case "$var" in
    --cpu=*)
        input_cpu="${var/--cpu=/}"
        ;;
    --cpu)
        input_cpu="-1"
        ;;
    --thread=*)
        process="${var/--thread=/}"
        ;;
    --thread)
        thread="-1"
        ;;
    --peer=*)
        process="${var/--peer=/}"
        ;;
    --peer)
        peer="-1"
        ;;
    *)
        if [ "$input_cpu" = "-1" ]; then
            input_cpu="$var"
        elif [ "$thread" = "-1" ]; then
            thread="$var"
        elif [ "$peer" = "-1" ]; then
            peer="$var"
        fi
        ;;
    esac
done

function parse_input_cpu() {
    input_cpu=${1// /}
    IFS_BAK="$IFS"
    IFS=","
    input_cpu=($input_cpu)
    input_cpu_len=${#input_cpu[@]}

    parsed_cpu=""
    parsed_cpu_idx=0
    for(( i = 0; i < input_cpu_len; i ++ ))
    do
        IFS="-"
        current_group=(${input_cpu[$i]})
        if [[ ${#current_group[@]} == 1 ]]; then
            parsed_cpu[$parsed_cpu_idx]=$current_group
            parsed_cpu_idx=$(( $parsed_cpu_idx + 1 ))
        elif [[ ${#current_group[@]} == 2 ]]; then
            current_group_start=${current_group[0]}
            current_group_end=${current_group[1]}
            current_group_cpu_num=$(( $current_group_end-$current_group_start+1 ))
            for (( j = 0; j < current_group_cpu_num; j ++ ))
            do
                parsed_cpu[$parsed_cpu_idx]=$(( $current_group_start+$j ))
                parsed_cpu_idx=$(( $parsed_cpu_idx + 1 ))
            done
        fi
    done

    IFS="$IFS_BAK"
    echo ${parsed_cpu[@]}
}

function start_boringtun_process() {
    process=$1
    core_list=$2

    echo "boringtun is binded to core $core_list"
    echo "cmdline: taskset -c $core_list ./target/debug/boringtun-cli --disable-drop-privileges -v trace -t $thread wg0"
    taskset -c $core_list ./target/debug/boringtun-cli --disable-drop-privileges -v trace -t $thread wg0
}

function configure_wg() {
    peer=$1

    for (( i = 0; i < peer; i ++ ))
    do
        key=$(cat ./key/publickey${i})
	wg set wg0 peer $key allowed-ips 192.0.$((0 + $i)).$((2 + $i))/32,8.0.0.0/24,192.168.0.0/16,4.0.0.0/24 endpoint 192.168.3.2:$((51820 + $i))
        route add -host 8.0.0.$((1 + $i)) dev ens785f0
    done
}

if [[ -z "$peer" ]]; then
    echo "lack of peer number, will not start boringtun!"
    exit 3
elif [[ -n "$input_cpu" ]]; then
    if [[ -z "$thread" ]]; then
        thread=4
    fi
    #input_cpu=$(parse_input_cpu "${input_cpu[@]}")
    echo "input_cpu $input_cpu"
    start_boringtun_process $thread "${input_cpu[@]}"
    
    ip address add 192.0.0.1/24 dev wg0
    wg set wg0 private-key ./privatekey
    wg set wg0 listen-port 51820
    ip link set wg0 up

    configure_wg $peer
fi
