# example5 — 코드 재사용 공격: Return-to-libc와 ROP

**Return-to-libc**와 **Return-Oriented Programming** 실습입니다.
DEP/NX는 주입된 쉘코드를 실행하지 못하게 만들므로(example3), 여기서는 코드를
주입하는 대신 **이미 실행 가능한 코드를 재사용**합니다 — 먼저 취약한 바이너리
안에 이미 들어 있는 함수, 그다음 libc 함수, 마지막으로 작은 명령어 가젯 순으로
재사용해 쉘을 얻습니다.

- **Part 0 — 바이너리 자체 코드로 리턴하기.**
  DEP는 *스택 실행*만 막을 뿐 오버플로우 자체는 막지 못합니다. 리턴 주소를
  덮어써서 프로그램이 평소에는 호출하지 않는 함수로 점프합니다.
- **Part A — Return-to-libc.** 임의로 심어둔 함수 대신 libc의
  `system()`으로 리턴하고, ESP lifting용 `pop; ret`로 함수 호출 두 개를 체이닝합니다.
- **Part B — ROP와 ASLR.** 가젯으로 write 프리미티브를 만들고, 레지스터를
  채우는 ROP로 raw `execve` 시스템콜을 호출한 뒤, 마지막으로 유출된 libc 포인터로
  ASLR을 우회합니다.

> **진행 순서:** 오버플로우와 DEP/NX를 다루는 example3 이후에 진행하세요.
> Vagrant VM(`/vagrant/labs/example5`) 안에서 작업하세요. 32비트 툴체인이
> 설치되어 있습니다. **Problem 0은 ASLR 여부와 무관하게 동작**합니다
> (libc를 전혀 건드리지 않음). **Problem 1-4는 ASLR off가 필요하고, Problem 5는
> ASLR on이 필요합니다.**

> **이 실습은 전부 x86 32비트**입니다. 강의 자료의 "ROP for x86-64" 슬라이드는
> Problem 4로 구현됩니다 — 32비트 syscall ROP도 x86-64 체인이 RDI/RSI/RDX를
> 채우는 것과 똑같은 방식으로 호출 전에 레지스터를 채웁니다. 다만 32비트라서
> `int 0x80`을 씁니다.

## 빌드

```sh
make          # 모든 바이너리 빌드
make check    # pwn checksec (전부: No canary / NX enabled / No PIE)
make aslr-off # echo 0 > randomize_va_space   (Problem 1-4)
make aslr-on  # echo 2 > randomize_va_space   (Problem 5)
make clean
```

> **바이너리를 직접 실행하기.** 공유 폴더 `/vagrant`는 `noexec`로 마운트되어
> 있어서 `./ret2libc`를 실행하면 "Permission denied"가 뜹니다.
> 바이너리를 직접 실행하려면 로컬 디스크로 먼저 복사하세요:
> `cp ret2libc /tmp && /tmp/ret2libc`.

모든 바이너리는 `-m32 -mpreferred-stack-boundary=2 -O0 -fno-stack-protector
-fno-pic -no-pie -fcf-protection=none`를 공통으로 씁니다. 중요한 점은
`-z execstack`을 **쓰지 않는다**는 것입니다 — NX가 켜져 있으며, 그래서 코드
주입은 실패하고 코드 재사용이 필요해지는 겁니다.

| 바이너리 | 아키텍처 | 할 일 |
|--------|------|-------------|
| `ret2func` | x86 | 바이너리에 이미 있는 함수 `foo()`로 리턴 |
| `ret2libc` | x86 | `system("/bin/sh")` 한 번 호출 |
| `chain` | x86 | `setuid(0)` 후 `system("/bin/sh")` (ESP lifting) |
| `ropwrite` | x86 | write-what-where ROP 체인 -> `win()` |
| `ret2syscall` | x86 | syscall 레지스터 채우고 `int 0x80` -> `execve("/bin/sh")` |
| `leak32` | x86 | **ASLR on** 상태에서 유출된 libc 포인터로 ret2libc |

---

# Part 0 — 바이너리 자체 코드로 리턴하기

DEP/NX는 CPU가 *스택을 실행*하는 것만 막습니다. 리턴 주소를 망가뜨리는
오버플로우 자체는 막지 못합니다. 가장 단순하게 이를 확인하는 방법은
취약한 프로그램 안에 이미 컴파일되어 있지만 정상적인 흐름에서는 절대 호출되지
않는 함수로 리턴 주소를 돌리는 것입니다.

## Problem 0 — ret2func: 바이너리 안의 함수로 리턴하기

`ret2func.c`는 슬라이드 코드를 거의 그대로 따릅니다:

```c
int main(){ int x = 42; echo(); return 0; }
void echo(){ char buf[32]; gets(buf); puts(buf); }
void foo(){ system("/bin/sh"); }
```

`foo()`는 `main()`이나 `echo()`에서 전혀 호출되지 않습니다 — `echo()`의 리턴
주소를 `foo()` 주소로 덮어써야만 도달할 수 있습니다. 바이너리가 `-no-pie`로
빌드되었기 때문에 그 주소는 링크 타임에 고정됩니다.

직접 payload를 만들어서 `foo()`가 호출되도록 해보세요.

---

# Part A — Return-to-libc

실습을 위해서 잠시 ASLR을 끄겠습니다.

현재 ASLR 상태 확인:

```sh
cat /proc/sys/kernel/randomize_va_space   # 0=off, 1=보수적 랜덤화, 2=완전 랜덤화(기본값)
```

ASLR 끄기 (Problem 1-4 동안 유지):

```sh
make aslr-off
# 내부적으로는: echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

다른 실습으로 넘어가기 전에 다시 켜기:

```sh
make aslr-on
# 내부적으로는: echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
```

## Problem 1 — ret2libc: libc 함수 한 번 호출

리턴 주소를 고전적인 32비트 ret2libc 프레임으로 덮어씁니다:

```
[ &system ][ fake return addr ][ &"/bin/sh" ]
```

`main`이 리턴하면 `system`으로 "리턴해 들어가고", `system`은 호출자가 스택에
넣어뒀을 것으로 기대하는 위치에서 인자를 읽습니다 — 바로 우리가 넣은
`&"/bin/sh"`입니다. 이 문자열은 이미 libc 안에 들어 있습니다
(`strings libc.so.6 | grep /bin/sh`).

```sh
make aslr-off
```

위 프레임으로 payload를 만들어 보내보세요.

## Problem 2 — chain: ESP lifting으로 함수 두 개 체이닝

프레임 하나는 함수 하나만 호출합니다. 두 개를 호출하려면 첫 번째 호출의
인자가 두 번째 호출 전에 스택에서 제거되어야 합니다. 해결책은
소비된 인자만큼 ESP를 들어 올리는 `pop; ret` 가젯입니다:

```
[ &setuid ][ pop;ret ][ 0 ][ &system ][ &exit ][ &"/bin/sh" ]
```

`main` ret → `setuid(0)`; `setuid` ret → `pop;ret`가 `0`을 버림; ret →
`system("/bin/sh")`.

위 체인대로 payload를 만들어 보내보세요.

일반 사용자로 실행하면 `setuid(0)`이 -1을 반환해서 **root가 아닌** 쉘을
얻습니다 — 여기서 배우는 건 체이닝 메커니즘 자체입니다. 역사적으로
ret2libc가 왜 중요했는지 보려면, 바이너리를 setuid-root로 만들고 chain이
**root** 쉘을 따내는 걸 확인해 보세요:

```sh
cp chain /tmp/chain && sudo chown root:root /tmp/chain && sudo chmod u+s /tmp/chain
```

그 다음 `/tmp/chain`을 대상으로 같은 익스플로잇을 실행해서 `id`로
`uid=0(root)`을 확인해 보세요.

---

# Part B — ROP와 ASLR

Return-to-libc는 libc 함수 전체가 필요합니다. ROP는 이를 일반화해서, 각각
`ret`로 끝나는 작은 명령어 시퀀스("가젯")를 체이닝합니다. 그러면 스택 자체가
작은 프로그램이 됩니다.

## Problem 3 — ropwrite: write-what-where 프리미티브

`mov [ptr], 0x41414141; ret` 같은 가젯은 거의 존재하지 않으므로, 세 개의
가젯으로 write를 합성합니다:

```
A: pop eax ; ret          -> eax = &key
B: pop ebx ; ret          -> ebx = 0x41414141
C: mov [eax], ebx ; ret   -> *key = 0x41414141
stack: [A][&key][B][0x41414141][C][&win]
```

write가 끝나면 체인은 `win()`으로 리턴하고, `win()`은 `key` 값을 확인해서
쉘을 띄웁니다. 슬라이드의 정확한 가젯들이 존재하도록 이 바이너리는 작은
**가젯 농장(gadget farm)**을 포함하고 있습니다.

위 체인대로 payload를 만들어 보세요. 강의에서 설명하는 방식대로 직접
가젯을 찾아봐도 됩니다:

```sh
ROPgadget --binary ropwrite | grep -E 'pop eax ; ret|pop ebx ; ret|mov dword ptr \[eax\], ebx'
```

## Problem 4 — ret2syscall: 레지스터를 채우는 ROP로 raw 시스템콜 호출

x86-64 슬라이드("ROP for x86-64" 섹션)는 호출 전에 `pop` 가젯으로
RDI, RSI, RDX, ... 레지스터를 채웁니다. 32비트 syscall ABI도 같은 아이디어입니다:
레지스터를 채운 다음 시스템콜을 발생시킵니다. 여기서는 libc의 `system()`을
아예 거치지 않고 `int 0x80`으로 직접 `execve("/bin/sh", NULL, NULL)`을
호출합니다:

```
eax = 11 (__NR_execve)   ebx = &"/bin/sh"   ecx = 0 (argv)   edx = 0 (envp)

[pop eax;ret][11][pop ebx;ret][&binsh][pop ecx;ret][0][pop edx;ret][0][int 0x80]
```

정확한 조각들이 존재하도록 이 바이너리는 **가젯 농장**(네 개의 `pop reg; ret`
가젯과 `int 0x80`)과 `"/bin/sh"` 문자열을 포함하고 있습니다.

위 체인대로 payload를 만들어 보세요.

이건 *순수한* ROP 익스플로잇입니다 — libc 함수를 전혀 호출하지 않습니다 —
그리고 강의 슬라이드의 x86-64 레지스터-ROP 예제에 대응하는 32비트 버전입니다.

## Problem 5 — leak32: 유출된 포인터로 ASLR 우회하기

ASLR이 켜져 있으면 libc 베이스가 매 실행마다 랜덤해지므로 Problem 1-4의
고정 주소는 더 이상 통하지 않습니다. 하지만 ASLR은 **베이스**만 랜덤화할 뿐,
libc 내부의 오프셋은 고정되어 있습니다. 유출된 libc 주소 하나면
충분합니다:

ASLR이 실제로 켜져 있는지 확인하려면:

```sh
cat /proc/sys/kernel/randomize_va_space   # 2가 나와야 full ASLR이 켜진 상태
```

또는 `leak32`를 두 번 연달아 실행해서 출력되는 libc 주소가 매번 바뀌는지
확인해도 됩니다 — 바뀐다면 ASLR이 제대로 켜져 있는 겁니다.

```
libc_base = leaked_puts - libc.sym.puts
system    = libc_base   + libc.sym.system
```

그 다음은 Problem 1과 똑같은 32비트 ret2libc 프레임입니다. 이 유출 자체가
**memory disclosure**입니다. 이 바이너리는 포맷 스트링이나 overread
버그 대신, 실제로 ASLR에 의해 랜덤화된 libc 주소(`puts`, `dlsym`을 통해)를
출력하는 방식으로 그 상황을 시뮬레이션합니다.

```sh
make aslr-on
```

위 공식으로 libc base를 구해서 payload를 만들어 보세요. 끝나면 다른
실습을 위해 ASLR을 원복하세요:

```sh
sudo sysctl -w kernel.randomize_va_space=0
```
