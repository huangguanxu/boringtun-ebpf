#!/bin/bash

if [ "$#" -eq 0 ]; then
    echo "Usage: [options]"
    echo "--cpu <str>             Bind irqs to these CPUs, by default is all core."
    echo "--process <num>         Define how many process."
    echo "--genkey                Generate private & public key."
    exit 3
fi

input_cpu=""
process=""
gen_key=0

for var in "$@"; do
    case "$var" in
    --cpu=*)
        input_cpu="${var/--cpu=/}"
        ;;
    --cpu)
        input_cpu="-1"
        ;;
    --process=*)
        process="${var/--process=/}"
        ;;
    --process)
        process="-1"
        ;;
    --genkey)
        gen_key=1
        ;;
    *)
        if [ "$input_cpu" = "-1" ]; then
            input_cpu="$var"
        elif [ "$process" = "-1" ]; then
            process="$var"
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

    IFS_BAK="$IFS"
    IFS=" "
    core_list=($core_list)
    IFS="$IFS_BAK"

    core_list_len=${#core_list[@]}

    for (( i = 0; i < process; i ++ ))
    do
        core_idx=$((i % $core_list_len))
        core=${core_list[$core_idx]}
        echo "the $i process is binded to core $core"
        echo "cmdline: taskset -c $core ./target/debug/boringtun-cli --disable-drop-privileges -v trace -t 1 wg$i"
        taskset -c $core ./target/debug/boringtun-cli --disable-drop-privileges -v trace -t 1 wg$i
    done
}

function configure_wg() {
    process=$1
    for (( i = 0; i < process; i ++ ))
    do
        ip address add 192.0.${i}.$((2 + $i))/24 dev wg${i}
        wg set wg${i} private-key ./key/privatekey${i}
        wg set wg${i} listen-port $((51820 + $i))
        wg set wg${i} peer KPjuAHDTtk8UYC/6RCv68i0yFzidsdzRi7Yn2PbHtTo= allowed-ips 192.0.0.1/32,8.0.0.0/24,192.168.0.0/16,4.0.0.0/24 endpoint 192.168.3.2:51820
        ip link set wg${i} up
        route add -host 8.0.0.$((1 + $i)) dev wg${i}
    done
}

function generate_key() {
    process=$1
    mkdir -p key

    for (( i = 0; i < process; i ++ ))
    do
        wg genkey > ./key/privatekey${i}
        wg pubkey < ./key/privatekey${i} | tee ./key/publickey${i}
    done
}


if [ $gen_key = 1 ]; then
    generate_key $process
fi

if [[ -z "$process" ]]; then
    echo "lack of process number, will not start boringtun!"
    exit 3
elif [[ -n "$input_cpu" ]]; then
    input_cpu=$(parse_input_cpu "${input_cpu[@]}")
    start_boringtun_process $process "${input_cpu[@]}"
    configure_wg $process
fi
