# -基于Okamonto的身份识别协议实现-

一、简介：

Okamoto 身份识别协议由 T.Okamoto 于1992年在 Crypto 92 会议上提出。当时人们没有发现 Schnorr 身份识别协议是可证明安全的，T.Okamoto对 Schnorr 身份识别协议做了改进，这种改进假定所选择的计算参数保证Zp上的离散对数问题是安全的，所以Okamoto 身份识别协议是可证明安全的。Okamoto 方案和 Schnorr 方案的区别在于前者使用两个生成元α1,α2，当p与q较大时，计算离散对数问题是困难的，所以前者的安全性更高，但是 Okamoto 方案比 Schnorr 方案计算量更大，所以从实现效率来讲，Schnorr协议比前者更实用。

二、算法流程：

（1）事前准备： 

TA为协议选择参数：(i)大素数:p,q且q|p-1 (ii)α1,α2∈Zp为q阶元；TA对所有参加者保密c，其中c为以α1为底α2的对数，给出假定任何人不可能计算出c。TA选择签名方案和Hash函数。

（2）运行过程：

(i)   Alice的公钥为v= α1^ (-a1) * α2^(-a2) mod p,私钥为a1和a2,1≤a1,a2≤q-1

(ii)  Alice选择随机数k1,k2,0≤k1,k2≤q-1，

并计算：γ = α1^k1 * α2^k2 mod p

(iii) Alice传送证书Cert(Alice) = (ID(Alice), v, s)和γ给Bob

(iv)  Bob验证verTA (ID(Alice)||v,s) = True 	

(v)   Bob选择随机数r(1≤r≤2^t)，并传送r给Alice

(vi)  Alice计算y1 = k1+a1*r mod q和y2 = k2+a2*r mod q并传送y1和y2给Bob

(vii) Bob验证γ = α1^y1 * α2^y2 * v^r mod p

三、编程实现：

(1)编程语言：python

(2)编程环境：python3.85
