### Creating new canary

```bash
# Publish an empty directory at first and get IPNS key from here
$ ipfs daemon # Keep this running in another terminal
$ mkdir temp
$ ipfs add -r temp
added QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn temp
 0 B / ? [------------------------------------------------------------=]
$ ipfs name publish /ipfs/QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn
Published to k51qzi5uqu5djy1cju5u93u7hutmifdbvm1q426c8hcycv1sew72c04yn9bhor: /ipfs/QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn
# k51qzi5uqu5djy1cju5u93u7hutmifdbvm1q426c8hcycv1sew72c04yn9bhor is the IPNS key

# Creating a new canary
$ ./canarytail canary new mywebsite.com --ipfs_url="http://127.0.0.1:5001" --ipns_key="k51qzi5uqu5djy1cju5u93u7hutmifdbvm1q426c8hcycv1sew72c04yn9bhor"
Resolving IPNS key k51qzi5uqu5djy1cju5u93u7hutmifdbvm1q426c8hcycv1sew72c04yn9bhor
IPNS key resolved to /ipfs/QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn
Fetching existing canaries into /home/xyz/go/src/github.com/canarytail/client/canary.1627821912
Storing canary.1627821912.json into /home/xyz/go/src/github.com/canarytail/client/canary.1627821912
Adding /home/xyz/go/src/github.com/canarytail/client/canary.1627821912 to IPFS
New directory added to IPFS as /ipfs/QmTvZ8e22Pc3apNCvvtxWm8cR58Ve79buZLe3V5QNuXbCK
Publishing /ipfs/QmTvZ8e22Pc3apNCvvtxWm8cR58Ve79buZLe3V5QNuXbCK, this may take a while
{
    "canary": {
        "domain": "mywebsite.com",
        "pubkeys": [
            "zadBum6YQruwiuqS7oOig6m7GITdm7QNhO9sbCEmoB8="
        ],
        "panickey": "2ATG1aU3tsfEJgAN0El//vFEtlMnfRkPqymV+gUYejs=",
        "version": "0.1",
        "release": "2021-08-01T18:15:12+05:30",
        "expiry": "2021-08-31T18:15:12+05:30",
        "freshness": "00000000000000000003f4fcbb59a7aaff7ce97dfee367085116802a9c4dadf0",
        "codes": [
            "cease",
            "raid",
            "seize",
            "xopers",
            "gag",
            "subp",
            "trap",
            "war",
            "duress",
            "xcred"
        ],
        "ipns_key": "k51qzi5uqu5djy1cju5u93u7hutmifdbvm1q426c8hcycv1sew72c04yn9bhor"
    },
    "signatures": {
        "zadBum6YQruwiuqS7oOig6m7GITdm7QNhO9sbCEmoB8=": {
            "domain": "XmLYvsErGM/MeYT4jLUeLRu24gbakYiLmhvLm9iIyJP1bi6R7ycLlip8GNrWlYQVo0CBSUNCLel5pP7EmacNCA==",
            "pubkeys": "ScgELMSf6VI63jilHLKHZkr8RLto7d7/5Vze5Kzp5OOWnI1GrYkD3LlHAB4/pg4pPiTwcUmevlYZ13d14F8gCQ==",
            "panickey": "6VqP0gld3aR+0X6otAvc0NG9VrKdJ86quaky+FTBPhnO0FsMhi5qhszPqv9PHyJ8rCsrd95Ulxp4LF2jEekTBA==",
            "version": "78h93YlCGG8ne/6sk+GkjsILxkhr3IWqhEues5HDI1Nxk4+qSvjsNCsfE4br9tFiIphgQxcHFrCVy5Xuw3wjAg==",
            "release": "RP03PNzZOe48q6oO1A2oNaMV1gLAgTt2S89qEzrLZM0o4vgqrkzncKxWc6+cB1oUCa9NTtn092AjpmrMOBJ4CQ==",
            "expiry": "itEbI4dmyHSCJw3RRWChFZl7CbebKdlVmnwvBecGGA7bi4JPW1UJhPb5TkK6N9cxwHS9nci3Z01B6mWQLoztDA==",
            "freshness": "MWx2v9HOcIKET85aTRehgYPGTHzwj6Qu/1lx8qHctmWAah6f1GajMqBddyJWZF1sNv3DhOiL1dK+ZYsWqeVcDA==",
            "codes": "W58rXfl0B2iGI/43uFF9PRjH/BJtOfCHz6brBOBwaxXQhqBqPAmVKol/7H1lmqknHcyDnbbuNnJ81s94aDKZAQ==",
            "ipns_key": "V97ZZera6JZ5/j3xyXyaZri/6Wmxj0F8Nn8JF/BpmfrlRH1GhQPU7NHeLWXjLmcUXRxA7Een0RsO7FFPWtT0Cw=="
        }
    }
}
```

### Reading the canary from IPNS/IPFS

```bash
$ ipfs resolve -r /ipns/k51qzi5uqu5djy1cju5u93u7hutmifdbvm1q426c8hcycv1sew72c04yn9bhor
/ipfs/QmTvZ8e22Pc3apNCvvtxWm8cR58Ve79buZLe3V5QNuXbCK
$ ipfs ls /ipfs/QmTvZ8e22Pc3apNCvvtxWm8cR58Ve79buZLe3V5QNuXbCK          
QmZ4JtgaaK71EYRnuxW2cTbLjFHJ1YpsKyHDjMfgcaRVmk 1877 canary.1627821912.json
$ ipfs cat /ipfs/QmZ4JtgaaK71EYRnuxW2cTbLjFHJ1YpsKyHDjMfgcaRVmk
{
    "canary": {
        "domain": "mywebsite.com",
        "pubkeys": [
            "zadBum6YQruwiuqS7oOig6m7GITdm7QNhO9sbCEmoB8="
        ],
        "panickey": "2ATG1aU3tsfEJgAN0El//vFEtlMnfRkPqymV+gUYejs=",
        "version": "0.1",
        "release": "2021-08-01T18:15:12+05:30",
        "expiry": "2021-08-31T18:15:12+05:30",
        "freshness": "00000000000000000003f4fcbb59a7aaff7ce97dfee367085116802a9c4dadf0",
        "codes": [
            "cease",
            "raid",
            "seize",
            "xopers",
            "gag",
            "subp",
            "trap",
            "war",
            "duress",
            "xcred"
        ],
        "ipns_key": "k51qzi5uqu5djy1cju5u93u7hutmifdbvm1q426c8hcycv1sew72c04yn9bhor"
    },
    "signatures": {
        "zadBum6YQruwiuqS7oOig6m7GITdm7QNhO9sbCEmoB8=": {
            "domain": "XmLYvsErGM/MeYT4jLUeLRu24gbakYiLmhvLm9iIyJP1bi6R7ycLlip8GNrWlYQVo0CBSUNCLel5pP7EmacNCA==",
            "pubkeys": "ScgELMSf6VI63jilHLKHZkr8RLto7d7/5Vze5Kzp5OOWnI1GrYkD3LlHAB4/pg4pPiTwcUmevlYZ13d14F8gCQ==",
            "panickey": "6VqP0gld3aR+0X6otAvc0NG9VrKdJ86quaky+FTBPhnO0FsMhi5qhszPqv9PHyJ8rCsrd95Ulxp4LF2jEekTBA==",
            "version": "78h93YlCGG8ne/6sk+GkjsILxkhr3IWqhEues5HDI1Nxk4+qSvjsNCsfE4br9tFiIphgQxcHFrCVy5Xuw3wjAg==",
            "release": "RP03PNzZOe48q6oO1A2oNaMV1gLAgTt2S89qEzrLZM0o4vgqrkzncKxWc6+cB1oUCa9NTtn092AjpmrMOBJ4CQ==",
            "expiry": "itEbI4dmyHSCJw3RRWChFZl7CbebKdlVmnwvBecGGA7bi4JPW1UJhPb5TkK6N9cxwHS9nci3Z01B6mWQLoztDA==",
            "freshness": "MWx2v9HOcIKET85aTRehgYPGTHzwj6Qu/1lx8qHctmWAah6f1GajMqBddyJWZF1sNv3DhOiL1dK+ZYsWqeVcDA==",
            "codes": "W58rXfl0B2iGI/43uFF9PRjH/BJtOfCHz6brBOBwaxXQhqBqPAmVKol/7H1lmqknHcyDnbbuNnJ81s94aDKZAQ==",
            "ipns_key": "V97ZZera6JZ5/j3xyXyaZri/6Wmxj0F8Nn8JF/BpmfrlRH1GhQPU7NHeLWXjLmcUXRxA7Een0RsO7FFPWtT0Cw=="
        }
    }
}
```

### Updating canary

```bash
# Update 1: gag is removed
$ ./canarytail canary update mywebsite.com --GAG --ipfs_url="http://127.0.0.1:5001" --ipns_key="k51qzi5uqu5djy1cju5u93u7hutmifdbvm1q426c8hcycv1sew72c04yn9bhor"
Resolving IPNS key k51qzi5uqu5djy1cju5u93u7hutmifdbvm1q426c8hcycv1sew72c04yn9bhor
IPNS key resolved to /ipfs/QmTvZ8e22Pc3apNCvvtxWm8cR58Ve79buZLe3V5QNuXbCK
Fetching existing canaries into /home/xyz/go/src/github.com/canarytail/client/canary.1627822196
Using the latest canary canary.1627821912.json for the update
Storing canary.1627822196.json into /home/xyz/go/src/github.com/canarytail/client/canary.1627822196
Adding /home/xyz/go/src/github.com/canarytail/client/canary.1627822196 to IPFS
New directory added to IPFS as /ipfs/QmTgdpfnJGhHB4waFEKp27vRdbKEZyPANW8edBSc2ki6yd
Publishing /ipfs/QmTgdpfnJGhHB4waFEKp27vRdbKEZyPANW8edBSc2ki6yd, this may take a while
{
    "canary": {
        "domain": "mywebsite.com",
        "pubkeys": [
            "zadBum6YQruwiuqS7oOig6m7GITdm7QNhO9sbCEmoB8="
        ],
        "panickey": "2ATG1aU3tsfEJgAN0El//vFEtlMnfRkPqymV+gUYejs=",
        "version": "0.1",
        "release": "2021-08-01T18:19:56+05:30",
        "expiry": "2021-08-31T18:19:56+05:30",
        "freshness": "00000000000000000003f4fcbb59a7aaff7ce97dfee367085116802a9c4dadf0",
        "codes": [
            "cease",
            "seize",
            "xcred",
            "xopers",
            "war",
            "subp",
            "trap",
            "duress",
            "raid"
        ],
        "ipns_key": "k51qzi5uqu5djy1cju5u93u7hutmifdbvm1q426c8hcycv1sew72c04yn9bhor"
    },
    "signatures": {
        "zadBum6YQruwiuqS7oOig6m7GITdm7QNhO9sbCEmoB8=": {
            "domain": "XmLYvsErGM/MeYT4jLUeLRu24gbakYiLmhvLm9iIyJP1bi6R7ycLlip8GNrWlYQVo0CBSUNCLel5pP7EmacNCA==",
            "pubkeys": "ScgELMSf6VI63jilHLKHZkr8RLto7d7/5Vze5Kzp5OOWnI1GrYkD3LlHAB4/pg4pPiTwcUmevlYZ13d14F8gCQ==",
            "panickey": "6VqP0gld3aR+0X6otAvc0NG9VrKdJ86quaky+FTBPhnO0FsMhi5qhszPqv9PHyJ8rCsrd95Ulxp4LF2jEekTBA==",
            "version": "78h93YlCGG8ne/6sk+GkjsILxkhr3IWqhEues5HDI1Nxk4+qSvjsNCsfE4br9tFiIphgQxcHFrCVy5Xuw3wjAg==",
            "release": "1R0L7367Z6oN1p/8pjrBHPeP8gAFrhIkC4JsdGLjRqH/AW6AbVo2/ZCR77/rFD7xTIBBZVGRwj3ISzfqT428AQ==",
            "expiry": "85psqkKcO+cT3c4E4iQDzF8orsVcW/YmdgSQkK/fng0ZVqG6ECq70Xsx0YKJH7cMSvjwmPFUyDRsJvdj8xYBDw==",
            "freshness": "MWx2v9HOcIKET85aTRehgYPGTHzwj6Qu/1lx8qHctmWAah6f1GajMqBddyJWZF1sNv3DhOiL1dK+ZYsWqeVcDA==",
            "codes": "HlmySYabb8shHnxTkoJ5iU+qkMFX15ZOh8NlNrnzHdG3ArqN5feIIBmBfsYWoCCR0TzWfIiZsmRbVZaLHxqTDA==",
            "ipns_key": "V97ZZera6JZ5/j3xyXyaZri/6Wmxj0F8Nn8JF/BpmfrlRH1GhQPU7NHeLWXjLmcUXRxA7Een0RsO7FFPWtT0Cw=="
        }
    }
}

# Update 2: war is removed
$ ./canarytail canary update mywebsite.com --WAR --ipfs_url="http://127.0.0.1:5001" --ipns_key="k51qzi5uqu5djy1cju5u93u7hutmifdbvm1q426c8hcycv1sew72c04yn9bhor"
Resolving IPNS key k51qzi5uqu5djy1cju5u93u7hutmifdbvm1q426c8hcycv1sew72c04yn9bhor
IPNS key resolved to /ipfs/QmTgdpfnJGhHB4waFEKp27vRdbKEZyPANW8edBSc2ki6yd
Fetching existing canaries into /home/xyz/go/src/github.com/canarytail/client/canary.1627822237
Using the latest canary canary.1627822196.json for the update
Storing canary.1627822237.json into /home/xyz/go/src/github.com/canarytail/client/canary.1627822237
Adding /home/xyz/go/src/github.com/canarytail/client/canary.1627822237 to IPFS
New directory added to IPFS as /ipfs/QmV5S1Umrt7C1z9F8LCsbfWz14HgRGjroA4w83ea8jngCu
Publishing /ipfs/QmV5S1Umrt7C1z9F8LCsbfWz14HgRGjroA4w83ea8jngCu, this may take a while
{
    "canary": {
        "domain": "mywebsite.com",
        "pubkeys": [
            "zadBum6YQruwiuqS7oOig6m7GITdm7QNhO9sbCEmoB8="
        ],
        "panickey": "2ATG1aU3tsfEJgAN0El//vFEtlMnfRkPqymV+gUYejs=",
        "version": "0.1",
        "release": "2021-08-01T18:20:37+05:30",
        "expiry": "2021-08-31T18:20:37+05:30",
        "freshness": "00000000000000000003f4fcbb59a7aaff7ce97dfee367085116802a9c4dadf0",
        "codes": [
            "trap",
            "duress",
            "raid",
            "seize",
            "xopers",
            "gag",
            "subp",
            "cease",
            "xcred"
        ],
        "ipns_key": "k51qzi5uqu5djy1cju5u93u7hutmifdbvm1q426c8hcycv1sew72c04yn9bhor"
    },
    "signatures": {
        "zadBum6YQruwiuqS7oOig6m7GITdm7QNhO9sbCEmoB8=": {
            "domain": "XmLYvsErGM/MeYT4jLUeLRu24gbakYiLmhvLm9iIyJP1bi6R7ycLlip8GNrWlYQVo0CBSUNCLel5pP7EmacNCA==",
            "pubkeys": "ScgELMSf6VI63jilHLKHZkr8RLto7d7/5Vze5Kzp5OOWnI1GrYkD3LlHAB4/pg4pPiTwcUmevlYZ13d14F8gCQ==",
            "panickey": "6VqP0gld3aR+0X6otAvc0NG9VrKdJ86quaky+FTBPhnO0FsMhi5qhszPqv9PHyJ8rCsrd95Ulxp4LF2jEekTBA==",
            "version": "78h93YlCGG8ne/6sk+GkjsILxkhr3IWqhEues5HDI1Nxk4+qSvjsNCsfE4br9tFiIphgQxcHFrCVy5Xuw3wjAg==",
            "release": "3Idu4G6AIZkCi1I4s++fUpKjB5K1rr/oHmdJ3JeOxEtUt/LAeuIaExOJhwbs3TUnGTH08vNpAHMJzO9F8GoGDw==",
            "expiry": "pPs4fx7J+YAEdGwdfTbyxq8LLMhJf/CTcIeoaO25+9dLd4Kq5vkN55zqgkpDfnNcDTGaYnaIHKaDKqvUA+COCg==",
            "freshness": "MWx2v9HOcIKET85aTRehgYPGTHzwj6Qu/1lx8qHctmWAah6f1GajMqBddyJWZF1sNv3DhOiL1dK+ZYsWqeVcDA==",
            "codes": "nGi1q02rxUZioYXURUxqk4ndT9BCt1pAi44lZbtTaT1hZVjvYiT4kh9ehmzAmHCHSMgO4Fr0WD0ih8b6bog5Dw==",
            "ipns_key": "V97ZZera6JZ5/j3xyXyaZri/6Wmxj0F8Nn8JF/BpmfrlRH1GhQPU7NHeLWXjLmcUXRxA7Een0RsO7FFPWtT0Cw=="
        }
    }
}

# Checking the files in IPNS
$ ipfs resolve -r /ipns/k51qzi5uqu5djy1cju5u93u7hutmifdbvm1q426c8hcycv1sew72c04yn9bhor                                                                         
/ipfs/QmV5S1Umrt7C1z9F8LCsbfWz14HgRGjroA4w83ea8jngCu
$ ipfs ls /ipfs/QmV5S1Umrt7C1z9F8LCsbfWz14HgRGjroA4w83ea8jngCu
QmZ4JtgaaK71EYRnuxW2cTbLjFHJ1YpsKyHDjMfgcaRVmk 1877 canary.1627821912.json
QmRxV6dZpz4t5aBeuWjdkqdh9LnqQH39CBYKW2EM3dDs4d 1858 canary.1627822196.json
QmXBhfeQcZJM5dwdt4FiY6oboPj5FLxB4Umxh5tsuFLQpV 1858 canary.1627822237.json
```
