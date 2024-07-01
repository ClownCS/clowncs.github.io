---
weight: 1
title: "UIUCTF2024"
date: 2024-07-01
lastmod: 2024-07-01
draft: false
author: "clowncs"
authorLink: "https://clowncs.github.io"
description: "Solutions for some challenges in UIUCTF 2024"
tags: ["RE", "2024"]
categories: ["Writeups"]

lightgallery: true

toc:
  enable: true
---
Solutions for some challenges in UIUCTF 2024

<!--more-->
# UIUCTF

This CTF i did 3 challenges but one of it is unintended ( using strings | grep ). So I will put writeup on 2 challenges i did and the revenge challenge that I couldn't afford to do it in time.


## Summarize

Simple z3 problem so i just put my script here

```python
from z3 import *


def add(a1, a2):
    return a1 + a2

def minus(a1, a2):
    return add(a1, -a2)

def mul(a1, a2):
    return a1 * a2  


def xor(a1, a2):
    return a1 ^ a2


def and_(a1, a2):    
    return a1 & a2


s = Solver()

data = [BitVec(f'data_{i}', 32) for i in range(7)]

for i in range(7):
    s.add(data[i] <= 999999999)
    s.add(data[i] > 100000000)

v7 = minus(data[0], data[1])
v18 = add(v7, data[2]) % 0x10AE961
v19 = add(data[0], data[1]) % 0x1093A1D
v8 = mul(2, data[1])
v9 = mul(3, data[0])
v10 = minus(v9, v8)
v20 = v10 % xor(data[0], data[3])
v11 = add(data[2], data[0])
v21 = and_(data[1], v11) % 0x6E22
v22 = add(data[1], data[3]) % data[0]
v12 = add(data[3], data[5])
v23 = xor(data[2], v12) % 0x1CE628
v24 = minus(data[4], data[5]) % 0x1172502
v25 = add(data[4], data[5]) % 0x2E16F83

s.add(v18 == 0x3F29B9)
s.add(v19 == 9166034)
s.add(v20 == 0x212C944D)
s.add(v21 == 12734)
s.add(v22 == 0x2038C43C)
s.add(v23 == 1279714)
s.add(v24 == 17026895)
s.add(v25 == 23769303)

if s.check() == sat:
    model = s.model()
    original_data_values = [model[data[i]].as_long() for i in range(6)]
    print(original_data_values)
else:
    print("No solution found")
```

Flag: ***uiuctf{2a142dd72e87fa9c1456a32d1bc4f77739975e5fcf5c6c0}***

## Pwnymaps

```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // ebx
  char v5; // [rsp+13h] [rbp-107Dh]
  unsigned __int16 v6; // [rsp+14h] [rbp-107Ch]
  unsigned __int16 v7; // [rsp+16h] [rbp-107Ah]
  unsigned __int16 v8; // [rsp+18h] [rbp-1078h]
  int v9; // [rsp+1Ch] [rbp-1074h] BYREF
  unsigned int v10; // [rsp+20h] [rbp-1070h] BYREF
  unsigned int v11; // [rsp+24h] [rbp-106Ch] BYREF
  int i; // [rsp+28h] [rbp-1068h]
  int j; // [rsp+2Ch] [rbp-1064h]
  int v14; // [rsp+30h] [rbp-1060h]
  unsigned int k; // [rsp+34h] [rbp-105Ch]
  int m; // [rsp+38h] [rbp-1058h]
  int n; // [rsp+3Ch] [rbp-1054h]
  int ii; // [rsp+40h] [rbp-1050h]
  unsigned int v19; // [rsp+44h] [rbp-104Ch]
  int v20; // [rsp+48h] [rbp-1048h]
  unsigned int v21; // [rsp+4Ch] [rbp-1044h]
  __int64 v22; // [rsp+50h] [rbp-1040h]
  __int64 v23; // [rsp+58h] [rbp-1038h]
  __int64 v24; // [rsp+60h] [rbp-1030h]
  unsigned __int64 v25; // [rsp+68h] [rbp-1028h]
  char v26[24]; // [rsp+70h] [rbp-1020h]
  unsigned __int64 v27; // [rsp+1078h] [rbp-18h]
  __int64 savedregs; // [rsp+1090h] [rbp+0h] BYREF

  v27 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  for ( i = 0; i <= 511; ++i )
  {
    for ( j = 0; j <= 7; ++j )
      *((_BYTE *)&savedregs + 8 * j + i - 4128) = 0;
  }
  puts("*****************");
  puts("* PWNYMAPS v0.1 *");
  puts("*****************");
  puts("The developer has only tested non-earth planetary systems. Please proceed with caution.");
  printf("%s", "Indicate your directional complexity level: ");
  __isoc99_scanf("%u", &v9);
  getchar();
  if ( (unsigned int)v9 > 0x200 )
    goto LABEL_26;
  v14 = 1;
  for ( k = 0; (int)k < v9; ++k )
  {
    printf("Indicate your 'Earth'-type coordinate %x {{hintText.toUpperCase()}}: ", k);
    __isoc99_scanf("%u%u", &v10, &v11);
    getchar();
    if ( v11 > 0xFFFFFFF )
      goto LABEL_26;
    v19 = v10 >> 8;
    v6 = (16 * v10) & 0xFF0 | (v11 >> 28);
    v7 = HIWORD(v11) & 0xFFF;
    v8 = EncodeMorton_12bit((unsigned __int16)v11 >> 10, (v11 >> 4) & 0x3F);
    v20 = EncodeMorton_24bit(v8, v7);
    v24 = EncodeMorton_48bit(v19, v7);
    v25 = (v24 << 12) | v6;
    v26[8 * k] = Unpad64Bit_8Bit(v25);
    v26[8 * k + 1] = Unpad64Bit_8Bit(v25 >> 1);
    v26[8 * k + 2] = Unpad64Bit_8Bit(v25 >> 2);
    v26[8 * k + 3] = Unpad64Bit_8Bit(v25 >> 3);
    v26[8 * k + 4] = Unpad64Bit_8Bit(v25 >> 4);
    v26[8 * k + 5] = Unpad64Bit_8Bit(v25 >> 5);
    v26[8 * k + 6] = Unpad64Bit_8Bit(v25 >> 6);
    v26[8 * k + 7] = Unpad64Bit_8Bit(v25 >> 7);
    v5 = v26[8 * k + 1];
    v26[8 * k + 1] = v26[8 * k + 5];
    v26[8 * k + 5] = v5;
    v21 = numberOfSetBits((unsigned __int16)((((unsigned __int8)v26[8 * k + 4] << 8) | (unsigned __int8)v26[8 * k + 5]) ^ (((unsigned __int8)v26[8 * k + 2] << 8) | (unsigned __int8)v26[8 * k + 3]) ^ ((unsigned __int8)v26[8 * k + 1] | ((unsigned __int8)v26[8 * k] << 8)) ^ (((unsigned __int8)v26[8 * k + 6] << 8) | (unsigned __int8)v26[8 * k + 7])));
    v3 = correct_checksums[k];
    if ( v3 != (unsigned int)hash(v21) )
      v14 = 0;
  }
  if ( v14 )
  {
    for ( m = 1; m < v9; ++m )
    {
      for ( n = 0; n <= 7; ++n )
      {
        numberOfSetBits(*((unsigned __int8 *)&savedregs + 8 * m + n - 4136));
        *((_BYTE *)&savedregs + 8 * m + n - 4128) = *((_BYTE *)&savedregs + 8 * m + n - 4128);
      }
    }
    for ( ii = 0; ii < v9; ++ii )
    {
      v22 = EncodeMorton_9x7bit(
              v26[8 * ii] & 0x7F,
              v26[8 * (ii % v9) + 1] & 0x7F,
              v26[8 * (ii % v9) + 2] & 0x7F,
              v26[8 * (ii % v9) + 3] & 0x7F,
              v26[8 * (ii % v9) + 4] & 0x7F,
              v26[8 * (ii % v9) + 5] & 0x7F,
              v26[8 * (ii % v9) + 6] & 0x7F,
              v26[8 * (ii % v9) + 7] & 0x7F,
              ((int)(unsigned __int8)v26[8 * ii + 6] >> 6) & 2 | ((int)(unsigned __int8)v26[8 * ii + 5] >> 5) & 4 | ((int)(unsigned __int8)v26[8 * ii + 4] >> 4) & 8 | ((int)(unsigned __int8)v26[8 * ii + 3] >> 3) & 0x10 | ((int)(unsigned __int8)v26[8 * ii + 2] >> 2) & 0x20 | ((int)(unsigned __int8)v26[8 * ii + 1] >> 1) & 0x40u | ((unsigned __int8)v26[8 * ii + 7] >> 7));
      v23 = (unsigned __int8)v26[8 * ii] >> 7;
      v22 |= v23 << 63;
      if ( v22 != correct[ii] )
        goto LABEL_26;
    }
    puts("You have reached your destination. PWNYMAPS does not support route plotting yet.");
    return 0;
  }
  else
  {
LABEL_26:
    puts("Continue straight for 500 meter(s) into Lake Michigan.");
    return 1;
  }
}
```

The code flow contains bunch of bitwise functions. But after all, we can regconise this.

- First, 32 bit hash can be unhash. 
- First attempt using z3 but not work :(
- Second for most of function can be revert. So this problem is kind of math. After suffering with my team we were able to recover x, y
```python
from Crypto.Util.number import *

ROUND = 335

correct_list = [
	0x00022640ABA57200, 0x0008004479D42852, 0x000880054948C092, 0x0008A41420193A02,
	0x00400541D1E04050, 0x004821117A352810, 0x004A0044C8404A12, 0x004A245518302A90,
	0x004A24557B20D892, 0x004A2650E3796050, 0x010A01442864E2D0, 0x0108A505E86D6802,
	0x0108A50451E1C880, 0x0108A505F3EC4010, 0x0108A70169E13012, 0x0108A7011AF138D0,
	0x0108860412910010, 0x01422700D0B40812, 0x0142865141E590C0, 0x0142A44551DCE092,
	0x0148A455682D2000, 0x014A2545A205AA92, 0x0400A0550A055212, 0x0402A1044BEC02C2,
	0x0408250471C01280, 0x04088145FB0D1852, 0x0408834010DC50C0, 0x04088211F1A83012,
	0x050227401A7400C2, 0x050202007AA948C0, 0x0500835170E80042, 0x044A071423453280,
	0x0448A30420E53000, 0x0442A601BA382A52, 0x04422751CA9DDAD0, 0x0442045472A068C0,
	0x0442810491C9B012, 0x0448245568915880, 0x044A2044C9FDE000, 0x0500054449210290,
	0x0502044461B93242, 0x0548851463309A82, 0x054825446B34E012, 0x05482105BA4CB042,
	0x0548230008D5C852, 0x0548230018DCF292, 0x0548261528B93800, 0x054807559B9928D0,
	0x0542A4D162197A02, 0x054801913325BA90, 0x0548848189197012, 0x054A8614B1ACB202,
	0x1002A31432D18890, 0x1008074499F8B090, 0x054A8304B2D578C0, 0x0540A75590C45A40,
	0x054023543B083AD0, 0x050826453AF42010, 0x1048A00422488082, 0x10488015436C0082,
	0x1048235023E1B840, 0x104822401ABC48C2, 0x1048071423B4E252, 0x10480714F370E090,
	0x104821D022ADEAD2, 0x1048A5D190B072D0, 0x104A81D0D074A850, 0x1102219079E8F2D2,
	0x110884C1BB8C0212, 0x1108A61051C988C2, 0x11020650F2100800, 0x104A824071B45812,
	0x10420700D1893A50, 0x10402750F19DF080, 0x100A8600D00128C0, 0x14088401FB31D250,
	0x14082101FB75B802, 0x114AA544C324F200, 0x140000546A19E842, 0x14000515BA2972C2,
	0x1400071099100A42, 0x114AA740731408C0, 0x114A82017160EA10, 0x1142230402F4C850,
	0x11408705A135F240, 0x1140A654614C0A80, 0x1148830563BD5A52, 0x114A831519A56080,
	0x14002355F03950D2, 0x14008091E8EDD210, 0x1400A08032B172D2, 0x140821852BC00050,
	0x144000C449118242, 0x1500001461ED8290, 0x144AA154B288C082, 0x144AA350001CD880,
	0x144AA7016BE07840, 0x1500231071E41AD2, 0x150026452BECCAD2, 0x144AA58039586A52,
	0x150024C17A053A42, 0x150024C173551A12, 0x150A25150A45F2D0, 0x154005558B45C802,
	0x15422005AA558842, 0x154880058B8DD252, 0x800001046854AAC0, 0x80020004E175F2C2,
	0x800280544931F000, 0x8008A054C3303A00, 0x80482541A1C5D2D2, 0x8048210038A542C0,
	0x80480114AA697840, 0x8042A015B3917A52, 0x804283502048A0C0, 0x8040A310F8D91240,
	0x8040A314221110D2, 0x8040A644BA291890, 0x80420615197C2892, 0x804AA254FBF8A8D0,
	0x8102A20478A938D2, 0x810A031539F55250, 0x81420701F81D7AD0, 0x814226501230BA12,
	0x814003412855CAC0, 0x810801047A995250, 0x8100A105137DEA90, 0x814AA454F1A5D840,
	0x814AA21028C50252, 0x814A8351C16C80D0, 0x814A2711F25CD250, 0x814A8245A234BAC2,
	0x814A2715F195D090, 0x814A80C189F828C0, 0x840082549B2D7A50, 0x840203459138A0C0,
	0x84088644D961AA00, 0x844087047B200A90, 0x8440A65453248A50, 0x8502A14533580092,
	0x85020414D0E5AA40, 0x844AA1055BFCA8C2, 0x8448A6009814CA52, 0x8448A60408A56AD0,
	0x844A8314B864B210, 0x85020304B2293842, 0x850803143B6DD212, 0x850A0655A1A97092,
	0x85088711DAD17A12, 0x8502271050A0B880, 0x844AA30050451AC0, 0x8542A005195DB8C0,
	0x8542A310022C9892, 0x8542A310B9C8D850, 0x8548260401907080, 0x854883556288F010,
	0x854A05D0088D1A12, 0x854A2180C3C91A52, 0x854A859409A96052, 0x9000219468CDC212,
	0x90020584302CB252, 0x900800D5E0AC2090, 0x90402494E9A49AC0, 0x904201C5A829B802,
	0x9040A245B2A40280, 0x900A0744D3E8B2C2, 0x900001C029517282, 0x854024D08325CA92,
	0x850A208121FC4810, 0x904A0515B26D8812, 0x904800459B3DE810, 0x9040871022A1D0C0,
	0x9042A251710D0812, 0x904206516838A290, 0x904222005115C050, 0x90482344A38930C0,
	0x904A0715EAE99A42, 0x910202059A1532D0, 0x9108065542FDF042, 0x910A2214A03C58D0,
	0x910A221058B4F052, 0x910282503BBC9852, 0x904A82109B2412D2, 0x904A8455B9F8C2D2,
	0x9100251598492A42, 0x91088414F0F52052, 0x91482545385998D2, 0x91482545710492C2,
	0x91488250C36DE0D2, 0x9148A7013AC000D2, 0x914887150B09F280, 0x9148871568412290,
	0x914A231480D42240, 0x94002215299CFA52, 0x9400A30508A91AC2, 0x9408870528981050,
	0x940A230589CC5212, 0x940A0445B0703092, 0x9440A405100DC292, 0x94428005B9FCC8D0,
	0x944884559A6D0852, 0x944A2404F21142D2, 0x9500241472CD1840, 0x9508A410F32C7AC0,
	0x950885558038C840, 0x95088554B3003202, 0x95088445DA497AC2, 0x950887509075E850,
	0x9508A301DBC11210, 0x9508A745E999F850, 0x9540260548056000, 0x9542A354CAC4A892,
	0x95488610FAA94250, 0x954A0700985032C2, 0x9542860009D18292, 0x950AA4445B513AC2,
	0x0020A75423B48880, 0x0020A640F855BA90, 0x0022260042397850, 0x002A045473F45052,
	0x002AA05552306240, 0x00608310A93D4A02, 0x00622351C0388850, 0x0062A3105204EA92,
	0x0062A31039B98A40, 0x006A044572B89842, 0x006AA2410204D842, 0x012002114AE010C0,
	0x012222117A910282, 0x01228315298C82D0, 0x012A24057B4D32D2, 0x016002014BB03090,
	0x0160020113C0B0C2, 0x012AA214E2D42082, 0x012AA214B134A812, 0x01602741DA91F0D2,
	0x016803552B74DAC2, 0x016A86544B7C5292, 0x042883048301A280, 0x04282641B07D6212,
	0x04288610033C4050, 0x04602150A944DA42, 0x0468805071794AD0, 0x046A24415ACC12C0,
	0x05200044E35D7A02, 0x05222504F1E19AD0, 0x052A2740E0BCD090, 0x05602751192D18D0,
	0x056203517A69D002, 0x0562265501008280, 0x052A8710415D8A90, 0x0528835109159840,
	0x05208641A8F070D2, 0x05202211EB05D8C2, 0x046A8300D1DD1A40, 0x04688255A3ACD2C0,
	0x0462A6556A442852, 0x04222745A8250AD0, 0x0420A3446BC4FA92, 0x0460814123A1FA82,
	0x046205416B91E010, 0x056AA1445A453012, 0x056AA210290C1AD0, 0x056A8700600DEA92,
	0x10200200704152C2, 0x10208255A09CB810, 0x102206544290C282, 0x102A865582498242,
	0x10602711394CA802, 0x10602710B97190C2, 0x1060A21152D138C0, 0x10620645A3B8F052,
	0x10680215A0A9EA10, 0x106A02448B0502C0, 0x106A875139187802, 0x106AA741A8892A82,
	0x1120060089C18850, 0x11602455D2F84010, 0x1160875062D1FA82, 0x112AA600D9510A40,
	0x112A2314C80C0A82, 0x11228241D9248A10, 0x11222601BAD46A80, 0x1122260109B060C0,
	0x1128A2404870F050, 0x11688500516DAA10, 0x116A055429A87AD0, 0x116A25459248A882,
	0x116A8405F2AC4AD0, 0x116AA701C8C402D0, 0x1420220153397A00, 0x142023140AB00A92,
	0x14202314C1851842, 0x1420275443F1E0C0, 0x14208615EB14EA52, 0x142827054A9C98C2,
	0x142A030542544280, 0x142AA65520E958C2, 0x14608710500132C2, 0x142AA651A2003252,
	0x1428224002A5D0C2, 0x14202750AB94CA10, 0x1560A64548F04A00, 0x1560071439743A02,
	0x1528264419ECF240, 0x15228715E3DC5810, 0x1520A3419294E0D2, 0x152223019A78A852,
	0x1528861098889050, 0x152A234061A85292, 0x152A234009C57A00, 0x152824451064E0C0,
	0x15200545B970F8C0, 0x15602500D3380042, 0x1560A55423398800, 0x1562A145EB6CA800,
	0x15688405335C88D0, 0x156A0015F89C2890, 0x156823018B357092, 0x156226006A3D6040,
	0x15680641CBF038D2, 0x156AA7111BF5B212, 0x8022865179FC2A92, 0x8022A31428A11AC0,
	0x802082044AC42240, 0x156A2645EACCCA10, 0x15688254B10D5A00, 0x1568871552381810,
	0x1568859162609AC0, 0x156821801B78CA50, 0x156281D1706CF892, 0x156081C5218122C0,
	0x156000D5ABB11090, 0x152A24D582389002, 0x152A00C461119880
]

correct_checksum = [
    0xCD4F2531, 0x23531B52, 0xC3C978E8, 0x08D5D6F3, 0x23531B52, 0xCD4F2531, 0xC3C978E8, 0x46A636A4,
	0x23531B52, 0x9A9F4A63, 0xC3C978E8, 0x23531B52, 0xCD4F2531, 0x23531B52, 0xC3C978E8, 0xC3C978E8,
	0xC3C978E8, 0x23531B52, 0xC3C978E8, 0xDFB6D245, 0xC3C978E8, 0xC3C978E8, 0x9A9F4A63, 0x08D5D6F3,
	0x08D5D6F3, 0xCD4F2531, 0xC3C978E8, 0x46A636A4, 0xC3C978E8, 0x23531B52, 0x04C8214B, 0x08D5D6F3,
	0xC3C978E8, 0x9A9F4A63, 0x23531B52, 0x9A9F4A63, 0xCD4F2531, 0x08D5D6F3, 0xDFB6D245, 0x9A9F4A63,
	0x23531B52, 0x23531B52, 0xC3C978E8, 0x08D5D6F3, 0x08D5D6F3, 0x9A9F4A63, 0xCD4F2531, 0x08D5D6F3,
	0x04C8214B, 0xC3C978E8, 0x04C8214B, 0x08D5D6F3, 0x08D5D6F3, 0x04C8214B, 0x9A9F4A63, 0xC3C978E8,
	0x9A9F4A63, 0xC3C978E8, 0x23531B52, 0xCD4F2531, 0xC3C978E8, 0x08D5D6F3, 0x46A636A4, 0x9A9F4A63,
	0xCD4F2531, 0x23531B52, 0x08D5D6F3, 0xDFB6D245, 0xC3C978E8, 0xCD4F2531, 0xC3C978E8, 0x9A9F4A63,
	0x23531B52, 0x23531B52, 0x9A9F4A63, 0xCD4F2531, 0x23531B52, 0xCD4F2531, 0xCD4F2531, 0xC3C978E8,
	0x23531B52, 0x04C8214B, 0x9A9F4A63, 0x08D5D6F3, 0x9A9F4A63, 0x08D5D6F3, 0x9A9F4A63, 0x08D5D6F3,
	0x23531B52, 0x08D5D6F3, 0xC3C978E8, 0x66A79298, 0x08D5D6F3, 0x9A9F4A63, 0x23531B52, 0x23531B52,
	0xCD4F2531, 0xC3C978E8, 0xC3C978E8, 0x9A9F4A63, 0x04C8214B, 0x9A9F4A63, 0x9A9F4A63, 0xDFB6D245,
	0xC3C978E8, 0xDFB6D245, 0x23531B52, 0xC3C978E8, 0xCD4F2531, 0x23531B52, 0x08D5D6F3, 0x9A9F4A63,
	0x04C8214B, 0x9A9F4A63, 0x04C8214B, 0xC3C978E8, 0x08D5D6F3, 0x9A9F4A63, 0x08D5D6F3, 0x9A9F4A63,
	0xC3C978E8, 0xC3C978E8, 0x04C8214B, 0x9A9F4A63, 0x08D5D6F3, 0x04C8214B, 0x08D5D6F3, 0x23531B52,
	0x08D5D6F3, 0x9A9F4A63, 0xC3C978E8, 0xC3C978E8, 0x46A636A4, 0x04C8214B, 0x08D5D6F3, 0x9A9F4A63,
	0xC3C978E8, 0x08D5D6F3, 0x23531B52, 0xC3C978E8, 0xC3C978E8, 0x23531B52, 0x9A9F4A63, 0x04C8214B,
	0x9A9F4A63, 0x08D5D6F3, 0x9A9F4A63, 0x9A9F4A63, 0x9A9F4A63, 0xC3C978E8, 0x23531B52, 0x04C8214B,
	0x9A9F4A63, 0xC3C978E8, 0x9A9F4A63, 0x9A9F4A63, 0x08D5D6F3, 0x04C8214B, 0x0A085B4C, 0xC3C978E8,
	0x04C8214B, 0x46A636A4, 0x9A9F4A63, 0xC3C978E8, 0x9A9F4A63, 0x04C8214B, 0x23531B52, 0x9A9F4A63,
	0x04C8214B, 0x08D5D6F3, 0x9A9F4A63, 0x46A636A4, 0x46A636A4, 0x9A9F4A63, 0xCD4F2531, 0x9A9F4A63,
	0x04C8214B, 0xC3C978E8, 0x04C8214B, 0x08D5D6F3, 0xC3C978E8, 0xC3C978E8, 0x08D5D6F3, 0x9A9F4A63,
	0x46A636A4, 0xC3C978E8, 0x23531B52, 0xC3C978E8, 0x08D5D6F3, 0x23531B52, 0x04C8214B, 0x04C8214B,
	0x04C8214B, 0xC3C978E8, 0xC3C978E8, 0xCD4F2531, 0x9A9F4A63, 0xC3C978E8, 0x08D5D6F3, 0x08D5D6F3,
	0x9A9F4A63, 0x9A9F4A63, 0x9A9F4A63, 0x08D5D6F3, 0xC3C978E8, 0xC3C978E8, 0xC3C978E8, 0x9A9F4A63,
	0x9A9F4A63, 0x04C8214B, 0x9A9F4A63, 0xC3C978E8, 0xCD4F2531, 0x23531B52, 0x9A9F4A63, 0x9A9F4A63,
	0x08D5D6F3, 0xC3C978E8, 0x08D5D6F3, 0xC3C978E8, 0xCD4F2531, 0x08D5D6F3, 0xC3C978E8, 0x9A9F4A63,
	0x04C8214B, 0x08D5D6F3, 0x04C8214B, 0x46A636A4, 0x9A9F4A63, 0xCD4F2531, 0x23531B52, 0x9A9F4A63,
	0xCD4F2531, 0xC3C978E8, 0x04C8214B, 0x08D5D6F3, 0xC3C978E8, 0x9A9F4A63, 0x0A085B4C, 0xC3C978E8,
	0xC3C978E8, 0x9A9F4A63, 0xCD4F2531, 0x04C8214B, 0x23531B52, 0xCD4F2531, 0x04C8214B, 0x08D5D6F3,
	0x0A085B4C, 0xC3C978E8, 0x46A636A4, 0x08D5D6F3, 0xC3C978E8, 0x9A9F4A63, 0xC3C978E8, 0xCD4F2531,
	0x08D5D6F3, 0x04C8214B, 0x23531B52, 0x08D5D6F3, 0xCD4F2531, 0x9A9F4A63, 0x08D5D6F3, 0x04C8214B,
	0x9A9F4A63, 0x08D5D6F3, 0x08D5D6F3, 0x46A636A4, 0x9A9F4A63, 0x46A636A4, 0xC3C978E8, 0xCD4F2531,
	0xC3C978E8, 0x04C8214B, 0x23531B52, 0x08D5D6F3, 0x23531B52, 0x08D5D6F3, 0x08D5D6F3, 0xC3C978E8,
	0x23531B52, 0x08D5D6F3, 0x9A9F4A63, 0x04C8214B, 0x08D5D6F3, 0x23531B52, 0x08D5D6F3, 0x9A9F4A63,
	0x08D5D6F3, 0xC3C978E8, 0x08D5D6F3, 0x9A9F4A63, 0x9A9F4A63, 0x08D5D6F3, 0x04C8214B, 0x08D5D6F3,
	0x04C8214B, 0x04C8214B, 0xC3C978E8, 0x08D5D6F3, 0x9A9F4A63, 0x9A9F4A63, 0x23531B52, 0x08D5D6F3,
	0x9A9F4A63, 0x9A9F4A63, 0x23531B52, 0x08D5D6F3, 0xC3C978E8, 0x46A636A4, 0x04C8214B, 0x08D5D6F3,
	0x46A636A4, 0xC3C978E8, 0x23531B52, 0x08D5D6F3, 0x23531B52, 0x23531B52, 0x9A9F4A63, 0x08D5D6F3,
	0xC3C978E8, 0x9A9F4A63, 0xC3C978E8, 0x23531B52, 0xCD4F2531, 0x04C8214B, 0xCD4F2531, 0x9A9F4A63,
	0x04C8214B, 0x04C8214B, 0x08D5D6F3, 0x04C8214B, 0xC3C978E8, 0x0A085B4C, 0xC3C978E8
]

def HIWORD(x):
    return (x & 0xffff0000) >> 16

def hash(a1):
    a1 = a1
    v2 = 73244475 * ((73244475 * (a1 ^ HIWORD(a1))) ^ ((73244475 * (a1 ^ HIWORD(a1))) >> 16))
    return HIWORD(v2) ^ v2


MOD = 1 << 32
inv_732 = inverse(73244475, MOD)

def dehash(a1):
    a1 ^= HIWORD(a1) # 73244475 * ((73244475 * (a1 ^ HIWORD(a1))) ^ ((73244475 * (a1 ^ HIWORD(a1))) >> 16))
    a1 = (a1 * inv_732) % MOD # (73244475 * (a1 ^ HIWORD(a1))) ^ ((73244475 * (a1 ^ HIWORD(a1))) >> 16)
    a1 ^= HIWORD(a1) # 73244475 * (a1 ^ HIWORD(a1))
    a1 = (a1 * inv_732) % MOD # a1 ^ HIWORD(a1)
    return a1 ^ HIWORD(a1)

def Pad7Bit(a1):
	return (a1 & 0x1) | \
    (a1 & 0x2) << 8 | \
    (a1 & 0x4) << 16 | \
    (a1 & 0x8) << 24 | \
    (a1 & 0x10) << 32 | \
    (a1 & 0x20) << 40 | \
    (a1 & 0x40) << 48

def Unpad7Bit(a1):
    return (a1 & 0x1) | \
    ((a1 >> 8) & 0x2) | \
    ((a1 >> 16) & 0x4) | \
    ((a1 >> 24) & 0x8) | \
    ((a1 >> 32) & 0x10) | \
    ((a1 >> 40) & 0x20) | \
    ((a1 >> 48) & 0x40)

def recover_correct():
    v26 = []
    for k in range(ROUND):
        base_v22 = correct_list[k]
        mask = 0b1000000001000000001000000001000000001000000001000000001
        res = []
        while len(res) < 9:
            res.append(base_v22 & mask)
            base_v22 ^= res[-1]
            base_v22 >>= 1
        for i in range(len(res)): res[i] = Unpad7Bit(res[i])
        tmp = res[-1]
        res = res[:-1]
        for i in range(len(res))[::-1]:
            res[i] = res[i] | ((tmp & 1) << 7)
            tmp >>= 1
        res[0] ^= (correct_list[k] >> 56) & 0x80
        v26 += res
    return v26

def Unpad64Bit_8Bit(a1):
    v2 = a1 & 0x1 | \
    (a1 & 0x100) >> 7 | \
    (a1 & 0x10000) >> 14 | \
    (a1 & 0x1000000) >> 21 | \
    (a1 & 0x100000000) >> 28 | \
    (a1 & 0x10000000000) >> 3 | \
    (a1 & 0x1000000000000) >> 10 | \
    (a1 & 0x100000000000000) >> 17
    return (v2 | ((v2 >> 32) & 0xff)) & 0xff

def deUnpad64Bit_8Bit(a1):

    res = (a1 & 0x1 | (a1 & 0x2) << 7 | (a1 & 0x4) << 14 | (a1 & 0x8) << 21 | \
            (a1 & 0x10) << 28 | (a1 & 0x20) << 35 | (a1 & 0x40) << 42 | (a1 & 0x80) << 49)
    return res

def Unpad24Bit(a1):
    base = 1
    res = 0
    for i in range(24):
        res += (a1 % 2) * base
        a1 >>= 2
        base <<= 1
    return res


def deEncodeMorton_48bit(v2):
    mask = 0x555555555555
    return Unpad24Bit(v2 & mask), Unpad24Bit((v2 >> 1) & mask)

def Pad24Bit(a1):
    v2 = a1 & 3 | \
    (a1 & 0xC) << 2 | \
    (a1 & 0x30) << 4 | \
    (a1 & 0xC0) << 6 | \
    (a1 & 0x300) << 8 | \
    (a1 & 0xC00) << 10 | \
    (a1 & 0x3000) << 12 | \
    (a1 & 0xC000) << 14 | \
    (a1 & 0x30000) << 16 | \
    (a1 & 0xC0000) << 18 | \
    (a1 & 0x300000) << 20 | \
    (a1 & 0xC00000) << 22
    return (v2 | (2 * v2)) & 0x555555555555

def EncodeMorton_48bit(a1, a2):
    v2 = Pad24Bit(a1)
    return v2 | (2 * Pad24Bit(a2))

def get_xy(v26): 
    xy = []
    for k in range(ROUND):
        v21 = dehash(correct_checksum[k])
        v26[8 * k + 1], v26[8 * k + 5] = v26[8 * k + 5], v26[8 * k + 1]
        assert v21 == bin((v26[8 * k + 1] | (v26[8 * k] << 8)) ^ ((v26[8 * k + 2] << 8) | v26[8 * k + 3]) ^ ((v26[8 * k + 4] << 8) | v26[8 * k + 5]) ^ ((v26[8 * k + 6] << 8) | v26[8 * k + 7])).count('1')
        
        v25 = 0
        for _ in range(8): v25 |= deUnpad64Bit_8Bit(v26[8 * k + _]) << _
        v24 = v25 >> 12
        v6 = v25 & 0xfff 
        v19, v7 = deEncodeMorton_48bit(v24)
        X = (v19 << 8) | (v6 >> 4)
        Y = (v7 << 16) | (((v6 & 0xf) << 28))
        xy.append([X, Y])
    return xy
xy = get_xy(recover_correct())
print(xy)
```

And the flag

```python=
import matplotlib.pyplot as plt

x = [23717296, 34143559, 41972267, 48531922, 70856741, 106220865, 118050931, 124537177, 124576491, 124631333, 186177341, 183620962, 183513704, 183612449, 183562627, 183523789, 178259969, 225512515, 229389964, 233324331, 250397952, 259622747, 281822387, 298873886, 309375128, 312075463, 311958700, 310747523, 427318286, 419479660, 412913670, 389330328, 382768512, 367118679, 360533757, 355238252, 361837443, 376228072, 390692640, 406347801, 422095254, 515156698, 511242019, 508680070, 508583527, 508583867, 509921728, 507341133, 502041074, 504670169, 513894819, 530950034, 567581257, 574192521, 529636844, 486348020, 475849181, 443079937, 650154506, 646198282, 643609540, 642272366, 640986935, 641055529, 643598207, 654117309, 664608581, 693433279, 715777043, 719598158, 690849856, 663268579, 623976917, 612216744, 597754188, 849472181, 844234690, 804857776, 806144870, 808829374, 808806486, 804826188, 796963697, 760225381, 749842356, 753710168, 781233399, 798254376, 811436207, 814077617, 817924543, 844165125, 872966678, 939832857, 937263658, 937168616, 938537444, 945075423, 946402943, 938539383, 946390486, 946388179, 997480381, 1010660962, 1027726918, 1048667831, 1074847580, 1090633662, 1099721632, 1120741840, 1182381759, 1179698236, 1175835108, 1170582007, 1167889164, 1154865300, 1154779279, 1156169929, 1160019275, 1204681549, 1237369295, 1259666613, 1295109629, 1298926547, 1276698236, 1242613941, 1221607289, 1340974820, 1338299415, 1335703053, 1333108405, 1334415326, 1333112489, 1334409548, 1351443957, 1360603916, 1386836816, 1420877913, 1424762453, 1507375115, 1495603028, 1473281870, 1457606263, 1457538429, 1469437841, 1494319558, 1511323315, 1529717163, 1521834483, 1500775368, 1473254620, 1572896716, 1574176459, 1574302437, 1583360424, 1587315617, 1597785299, 1599156439, 1605656871, 1616172595, 1630570391, 1645053193, 1684399836, 1696187330, 1690928152, 1664693150, 1612249530, 1550657147, 1530969185, 1731565123, 1711894369, 1689551532, 1707910211, 1697434393, 1698704933, 1717150092, 1731580630, 1761693085, 1781276582, 1799720173, 1799638951, 1770843847, 1736795295, 1739455039, 1752518998, 1789238535, 1853414095, 1853400734, 1854748463, 1861275663, 1857315768, 1857343769, 1867848980, 1883566071, 1892696286, 1924188293, 1934718131, 1932106123, 1960838715, 1971453549, 1991070791, 2002880575, 2019857604, 2061870588, 2059209316, 2059248018, 2057916926, 2059214693, 2060546193, 2063199205, 2086683936, 2111657803, 2124791861, 2133940638, 2107669019, 2078833118, 2164043336, 2162810841, 2170554853, 2200747175, 2211186996, 2224417906, 2237467205, 2245265275, 2245323348, 2267581126, 2278033126, 2281984140, 2302986266, 2308236829, 2338387359, 2348837257, 2348823438, 2344983818, 2344988483, 2356759471, 2384264958, 2410446011, 2458985240, 2456395059, 2460232741, 2489186038, 2525804669, 2540197020, 2550775282, 2574365405, 2608434857, 2625397965, 2635911842, 2641109528, 2612280921, 2593943236, 2561268143, 2554717934, 2542877908, 2525865660, 2515326279, 2440676445, 2430138363, 2493031418, 2503535393, 2681755011, 2680480989, 2679146363, 2684391614, 2693631937, 2704017978, 2746028566, 2759128898, 2759195278, 2764315084, 2770971559, 2785379185, 2802410524, 2814175714, 2818163034, 2820764229, 2892830753, 2898041850, 2883680340, 2874491994, 2844354129, 2841763192, 2841667884, 2865257381, 2930784081, 2940002813, 2943947594, 2946598013, 2951828509, 2956995056, 2958313563, 2958369990, 2960931628, 2963664759, 2993704654, 3004177464, 3018625262, 3031695774, 3018686871, 2991064750, 2961043057, 3169343600, 3157589458, 3127408564, 3115695329, 3101232943, 3109116743, 3131392645, 3143147707, 3143136752, 3127383852, 3090807788, 3161532422, 3170675264, 3185178432, 3198205517, 3204828489, 3193007531, 3177237796, 3190389199, 3220471699, 3249339739, 3251945692, 3229635860, 3211384433, 3196953840, 3199469761, 3199505116, 3192945269, 3181156331, 3164119324, 3155028105, 3144485506, 3137907400]
y = [70123520, 58982400, 47185920, 34734080, 30146560, 32112640, 41943040, 55050240, 65536000, 79298560, 34078720, 47841280, 59637760, 66846720, 80609280, 91095040, 119930880, 93061120, 80609280, 64225280, 47841280, 39976960, 39976960, 45875200, 58982400, 66191360, 85196800, 98304000, 86507520, 96337920, 98304000, 102891520, 101580800, 91750400, 83230720, 61603840, 51773440, 46530560, 43909120, 42598400, 43909120, 44564480, 44564480, 57671680, 67502080, 85196800, 106823680, 125173760, 150077440, 157941760, 139591680, 119275520, 119930880, 119275520, 119930880, 121896960, 120586240, 124518400, 36700160, 49807360, 70123520, 87818240, 103546880, 128450560, 138280960, 155975680, 159907840, 161218560, 158597120, 93716480, 94371840, 93061120, 93716480, 93716480, 92405760, 32112640, 32112640, 44564480, 45219840, 58327040, 83886080, 94371840, 96993280, 103546880, 105512960, 110100480, 117309440, 122552320, 131727360, 148766720, 154009600, 174325760, 176291840, 43909120, 53739520, 68157440, 82575360, 93061120, 108789760, 152043520, 165806080, 165806080, 39976960, 39976960, 39976960, 41287680, 41943040, 42598400, 42598400, 44564480, 4587520, 17694720, 37355520, 57016320, 68157440, 93716480, 102891520, 121241600, 123207680, 129761280, 127795200, 122552320, 97648640, 86507520, 71434240, 62259200, 58327040, 59637760, 67502080, 81264640, 99614720, 107479040, 130416640, 140247040, 121241600, 123207680, 126484480, 128450560, 128450560, 57671680, 59637760, 66846720, 83886080, 101580800, 117964800, 121241600, 121241600, 106823680, 98959360, 93061120, 92405760, 55705600, 70778880, 85196800, 100925440, 116654080, 135659520, 146145280, 169738240, 177602560, 186122240, 182190080, 176947200, 173670400, 124518400, 129761280, 134348800, 136970240, 140247040, 58327040, 58327040, 70123520, 97648640, 81264640, 92405760, 104202240, 117309440, 123863040, 117309440, 102236160, 93061120, 87818240, 86507520, 56360960, 55705600, 59637760, 55705600, 62914560, 79298560, 90439680, 108134400, 113377280, 100925440, 106168320, 106823680, 106168320, 106168320, 55050240, 55705600, 56360960, 58327040, 60948480, 62259200, 28835840, 39321600, 52428800, 66191360, 84541440, 98959360, 114688000, 113377280, 111411200, 96337920, 83886080, 67502080, 60948480, 103546880, 92405760, 79298560, 61603840, 65536000, 68812800, 81264640, 94371840, 85852160, 66846720, 73400320, 82575360, 98959360, 106168320, 66191360, 82575360, 90439680, 111411200, 117964800, 98959360, 107479040, 112721920, 102891520, 89784320, 70778880, 0, 26869760, 32768000, 45219840, 59637760, 77332480, 89784320, 100270080, 104857600, 76677120, 71434240, 72089600, 81920000, 93716480, 108789760, 115343360, 105512960, 111411200, 7208960, 15073280, 60948480, 68157440, 76677120, 92405760, 106168320, 111411200, 108134400, 89128960, 84541440, 98959360, 108789760, 106823680, 102891520, 89128960, 72744960, 67502080, 66846720, 77987840, 92405760, 110100480, 96993280, 90439680, 72089600, 76021760, 26869760, 35389440, 57671680, 66846720, 79953920, 100270080, 103546880, 109445120, 112066560, 115343360, 116654080, 115343360, 106823680, 92405760, 73400320, 70123520, 69468160, 114032640, 117964800, 119275520, 116654080, 90439680, 91750400, 85196800, 77332480, 67502080, 55050240, 55050240, 28835840, 37355520, 49807360, 57671680, 64225280, 74055680, 79298560, 82575360, 91095040, 98304000, 101580800, 111411200, 116654080, 118620160, 133693440, 149422080, 154664960, 165150720, 172359680, 174981120, 175636480, 176291840]

plt.figure(figsize=(20, 8))
plt.plot(x, y, linestyle='-', color='b')
plt.title('Line Plot of Given x, y Data')
plt.xlabel('x values')
plt.ylabel('y values')
plt.grid(True)
plt.show()
```

![image](https://github.com/clowncs/clowncs.github.io/assets/90112096/eba2a79c-950a-40ee-801d-dcb95eff1228)

Flag: ***uiuctf{i_prefer_pwnymaps}***

* https://github.com/Pusty/writeups/blob/master/UIUCTF2024/z3solve.py

## Wild Goose Chase

The challenge provides two file: dmp, pcap file. We can extract the malware from the pcap file. Recently, I'm really interest in malware stuff but this challenge is a bit cursed...

Before analysis anything i always take a quick look on DIE. And we got something interesting.

![image](https://github.com/clowncs/clowncs.github.io/assets/90112096/86454685-2398-4aa8-8637-47eeb108f876)

The zip file contains the Desktop Goose. Seems this a normal file `https://github.com/DesktopGooseUnofficial`. So at this moment, I have a theory that the malware we just extracted from pcap will unzip and run this subroutine and at the same time encrypt the data in some way.

Turn on IDA, find some strings related to zip

![image](https://github.com/clowncs/clowncs.github.io/assets/90112096/6220c995-7ebd-4882-9a5e-fc845a6fa05f)

Luckily we found this, trace back we found this function will unzip the file ``sub_1400243FC``

![image](https://github.com/clowncs/clowncs.github.io/assets/90112096/218208ae-827b-4b5c-ae11-b3e5ab5153a8)

Before trace that function, i want to take a look on the main function. So usually the main function will be after the line ``result = main_func`` in ``start`` 

```C
// write access to const memory has been detected, the output may be wrong!
__int64 sub_140001180()
{
  PVOID StackBase; // rsi
  signed __int64 v1; // rax
  int v2; // edi
  int v3; // ebx
  size_t v4; // rdi
  _QWORD *v5; // rax
  __int64 v6; // r12
  __int64 v7; // rbp
  size_t v8; // rdi
  __int64 v9; // rbx
  size_t v10; // rsi
  void *v11; // rax
  const void *v12; // rdx
  _QWORD *v13; // rdi
  __int64 result; // rax

  StackBase = NtCurrentTeb()->NtTib.StackBase;
  while ( 1 )
  {
    v1 = _InterlockedCompareExchange64(&qword_1414F60E0, (signed __int64)StackBase, 0i64);
    if ( !v1 )
    {
      v2 = 0;
      if ( unk_1414F60E8 == 1 )
        goto LABEL_20;
      goto LABEL_6;
    }
    if ( StackBase == (PVOID)v1 )
      break;
    Sleep(1000u);
  }
  v2 = 1;
  if ( unk_1414F60E8 == 1 )
  {
LABEL_20:
    amsg_exit(31i64);
    if ( unk_1414F60E8 == 1 )
      goto LABEL_21;
LABEL_9:
    if ( v2 )
      goto LABEL_10;
    goto LABEL_22;
  }
LABEL_6:
  if ( unk_1414F60E8 )
  {
    dword_1414F6008 = 1;
  }
  else
  {
    unk_1414F60E8 = 1;
    initterm(&qword_1414F9018, qword_1414F9028);
  }
  if ( unk_1414F60E8 != 1 )
    goto LABEL_9;
LABEL_21:
  initterm(&qword_1414F9000, &qword_1414F9010);
  unk_1414F60E8 = 2;
  if ( v2 )
    goto LABEL_10;
LABEL_22:
  _InterlockedExchange64(&qword_1414F60E0, 0i64);
LABEL_10:
  if ( TlsCallback_1 )
    TlsCallback_1(0i64, 2i64, 0i64);
  sub_14002FEC0();
  qword_1414F6170 = (__int64)SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)&loc_140030270);
  sub_14002F990(nullsub_1);
  sub_14002FCD0();
  v3 = dword_1414F6028;
  v4 = 8i64 * (dword_1414F6028 + 1);
  v5 = malloc(v4);
  v6 = qword_1414F6020;
  v7 = (__int64)v5;
  if ( v3 <= 0 )
  {
    v13 = v5;
  }
  else
  {
    v8 = v4 - 8;
    v9 = 0i64;
    do
    {
      v10 = strlen(*(const char **)(v6 + v9)) + 1;
      v11 = malloc(v10);
      *(_QWORD *)(v7 + v9) = v11;
      v12 = *(const void **)(v6 + v9);
      v9 += 8i64;
      memcpy(v11, v12, v10);
    }
    while ( v8 != v9 );
    v13 = (_QWORD *)(v7 + v8);
  }
  *v13 = 0i64;
  qword_1414F6020 = v7;
  sub_14002FAD0();
  _initenv = qword_1414F6018;
  result = sub_14000B7E0();
  dword_1414F6010 = result;
  if ( !dword_1414F600C )
    exit(result);
  if ( !dword_1414F6008 )
  {
    cexit();
    return (unsigned int)dword_1414F6010;
  }
  return result;
}
```
Inside ``sub_14000B7E0`` will have a main function that we need to take a close look. This case is ``sub_14000A1B5``, I'll change that to ``main``. The reason I tell this challenge is cursed because this function is really weird like I couldn't understand it by just static. When debugging it, i realize there is still one more binary in golang and seem this is the real malware. After extracting it, i put it on virustotal and got this

![image](https://github.com/clowncs/clowncs.github.io/assets/90112096/4c48828a-c928-406b-99bd-0fcb1e4b6bcc)

Seem this malware using SliverC2 framework so it must has some report or tools that able to analysis

* https://github.com/Immersive-Labs-Sec/SliverC2-Forensics
* https://www.immersivelabs.com/blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide
* https://github.com/BishopFox/sliver

First using this command to find payload `python sliver_pcap_parser.py --pcap noGoose.pcapng --filter http --domain_name "10.0.0.101"`

```bash
[+] Filtering for HTTP traffic
[+] Collecting Sessions

http://10.0.0.101/oauth2callback/oauth/api.html?bv=5849e5085&r=8r0345412
http://10.0.0.101/oauth2callback/oauth/api.html?bv=5849e5085&r=8r0345412
http://10.0.0.101/bootstrap.js?n=1393j5741
http://10.0.0.101/api.php?n=369d59499
http://10.0.0.101/api.php?n=369d59499
http://10.0.0.101/bootstrap.js?n=1393j5741
http://10.0.0.101/assets/array.js?n=11904w255
http://10.0.0.101/assets/array.js?n=11904w255
http://10.0.0.101/bundle/array.js?a=47928888
http://10.0.0.101/bundle/array.js?a=47928888
http://10.0.0.101/bundle/email.js?c=m38836m161
http://10.0.0.101/bundle/email.js?c=m38836m161
http://10.0.0.101/jquery.min.js?x=362006h71
http://10.0.0.101/jquery.min.js?x=362006h71
http://10.0.0.101/bundle/bootstrap.min.js?g=70928930
http://10.0.0.101/bundle/bootstrap.min.js?g=70928930
http://10.0.0.101/array.js?y=23510165
http://10.0.0.101/array.js?y=23510165
http://10.0.0.101/email.js?g=61309372
http://10.0.0.101/oauth/samples.php?f=27153358
http://10.0.0.101/oauth/samples.php?f=27153358
http://10.0.0.101/email.js?g=61309372
http://10.0.0.101/assets/array.js?o=68257360
http://10.0.0.101/assets/array.js?o=68257360
http://10.0.0.101/assets/backbone.js?g=50102x354
http://10.0.0.101/auth/authenticate/oauth/database/api.php?i=88894g737
http://10.0.0.101/auth/authenticate/oauth/database/api.php?i=88894g737
http://10.0.0.101/assets/backbone.js?g=50102x354
http://10.0.0.101/assets/bootstrap.js?t=80248i874
http://10.0.0.101/auth/samples.php?m=912l82j940
http://10.0.0.101/auth/samples.php?m=912l82j940
http://10.0.0.101/assets/bootstrap.js?t=80248i874
http://10.0.0.101/bundle/array.js?r=9565ah6438
http://10.0.0.101/bundle/array.js?r=9565ah6438
http://10.0.0.101/jquery.min.js?a=206_26352
http://10.0.0.101/oauth2callback/oauth/auth/samples.php?h=m31953704
http://10.0.0.101/oauth2callback/oauth/auth/samples.php?h=m31953704
http://10.0.0.101/jquery.min.js?a=206_26352
http://10.0.0.101/bootstrap.min.js?i=70189559
http://10.0.0.101/bootstrap.min.js?i=70189559
http://10.0.0.101/jquery.min.js?c=70013264
http://10.0.0.101/samples.php?f=t28564447
http://10.0.0.101/samples.php?f=t28564447
http://10.0.0.101/jquery.min.js?c=70013264
http://10.0.0.101/bundle/bootstrap.min.js?q=527119x64
http://10.0.0.101/bundle/bootstrap.min.js?q=527119x64
http://10.0.0.101/assets/backbone.js?w=4o1459034
http://10.0.0.101/auth/database/oauth2callback/api.php?n=59z33056
http://10.0.0.101/auth/database/oauth2callback/api.php?n=59z33056
http://10.0.0.101/assets/backbone.js?w=4o1459034
http://10.0.0.101/bundle/script.js?a=3429716u7
http://10.0.0.101/bundle/script.js?a=3429716u7
http://10.0.0.101/bootstrap.min.js?f=6151383b9
http://10.0.0.101/bootstrap.min.js?f=6151383b9
http://10.0.0.101/bundle/email.js?t=32872685
http://10.0.0.101/bundle/email.js?t=32872685
http://10.0.0.101/assets/bootstrap.min.js?w=67822d299
  [-] Found 15 probable Sliver Payloads
[!] Extraction Complete, if you have a key or process dump use the sliver-decrypy.py script
```

Second using this to decrypt `python3 sliver_decrypt.py --transport http --file_path http-sessions.json --force Goose.dmp `

```bash
[+] Finding all possible keys in Goose.dmp
  [-] Found 5391 possible keys
  [*] Keys will be tested during first decryption attempt
[+] Running HTTP Decoder
[+] Processing: http://10.0.0.101:80/oauth2callback/oauth/api.html?bv=5849e5085&r=8r0345412
  [-] Decoding: b64
  [!] Session Key: Unable to find a valid key for this session
[+] Processing: http://10.0.0.101:80/oauth2callback/oauth/api.html?bv=5849e5085&r=8r0345412
  [-] Decoding: b64
  [-] Session Key: ccb90e9bb8db3ef5e121d7cbba944bf1a0e16fdf8a8a0d543b960ce7989cda33
[+] Processing: http://10.0.0.101:80/api.php?n=369d59499
  [-] Decoding: gzip-b64
  [-] Session Key: ccb90e9bb8db3ef5e121d7cbba944bf1a0e16fdf8a8a0d543b960ce7989cda33
  [-] Message Type: 1
[=] Message Data
b'\n\ngoosechase\x12\x0fDESKTOP-DEQMME0\x1a$e1a84d56-400f-3cd4-a1f3-233922586739"\x15DESKTOP-DEQMME0\\Ronan*-S-1-5-21-1165601571-417196110-1223264716-10012,S-1-5-21-1165601571-417196110-1223264716-513:\x07windowsB\x05amd64H\x94)R\x18C:\\Users\\Ronan\\Goose.exeZ\x15https://10.0.0.101:80b\x1510 build 22631 x86_64h\x80\xb0\x9d\xc2\xdf\x01\x82\x01$aa00c4d8-3b17-4ff4-85cd-809c35cfd666\x88\x01\xe2\x9d\xb9\x91\xfd\xa0\x89\xb1\xfb\x01\x92\x01\x05en-US'
[+] Processing: http://10.0.0.101:80/array.js?y=23510165
  [-] Decoding: hex
  [-] Session Key: ccb90e9bb8db3ef5e121d7cbba944bf1a0e16fdf8a8a0d543b960ce7989cda33
  [-] Message Type: 5
[=] Message Data
b'\n\x01.J\x07\x10\x80\xb0\x9d\xc2\xdf\x01'
[+] Processing: http://10.0.0.101:80/oauth/samples.php?f=27153358
  [-] Decoding: b64
  [-] Session Key: ccb90e9bb8db3ef5e121d7cbba944bf1a0e16fdf8a8a0d543b960ce7989cda33
  [-] Message Type: 0
[=] Message Data
b'\n\x0eC:\\Users\\Ronan\x10\x01\x1a$\n\r.bash_history\x18\xc7\x01 \x80\x9c\xfc\xac\x06*\n-rw-rw-rw-\x1a\x1d\n\x07.dotnet\x10\x01 \x95\xb3\xed\xb2\x06*\ndrwxrwxrwx\x1a\x1c\n\x06.nuget\x10\x01 \xa5\xaf\xea\xb2\x06*\ndrwxrwxrwx\x1a%\n\x0f.templateengine\x10\x01 \xdd\xf9\xfe\xab\x06*\ndrwxrwxrwx\x1a"\n\x0c.vcpkg-clion\x10\x01 \xb0\x8f\xfc\xac\x06*\ndrwxrwxrwx\x1a#\n\r.vcpkg-clion1\x10\x01 \xad\x91\xfc\xac\x06*\ndrwxrwxrwx\x1a\x1d\n\x07AppData\x10\x01 \xd2\xe4\xfe\xab\x06*\ndrwxrwxrwx\x1aD\n\x10Application Data \xd2\xe4\xfe\xab\x06*\nLrw-rw-rw-2\x1eC:\\Users\\Ronan\\AppData\\Roaming\x1a1\n\x19Assessment Referral .pptx\x18\xc8\xbd\x01 \x8c\xfa\xad\xb2\x06*\n-rw-rw-rw-\x1a#\n\rCLionProjects\x10\x01 \xe8\x8d\xfc\xac\x06*\ndrwxrwxrwx\x1a\x1f\n\x08Cave.exe\x18\x80H \x96\x98\xf4\xb2\x06*\n-rw-rw-rw-\x1a\x1e\n\x08Confused\x10\x01 \xa7\xe9\xf2\xb2\x06*\ndrwxrwxrwx\x1a\x1e\n\x08Contacts\x10\x01 \xec\xe4\xfe\xab\x06*\ndr-xr-xr-x\x1aW\n\x07Cookies \xd2\xe4\xfe\xab\x06*\nLrw-rw-rw-2:C:\\Users\\Ronan\\AppData\\Local\\Microsoft\\Windows\\INetCookies\x1a\x1d\n\x07Desktop\x10\x01 \xfe\xee\xb7\xb3\x06*\ndr-xr-xr-x\x1a\x1f\n\tDocuments\x10\x01 \xad\xf9\xfe\xab\x06*\ndr-xr-xr-x\x1a\x1f\n\tDownloads\x10\x01 \x93\xe0\xb1\xb3\x06*\ndr-xr-xr-x\x1a\x1f\n\tFavorites\x10\x01 \xb2\xb6\xde\xb2\x06*\ndr-xr-xr-x\x1a"\n\tGoose.exe\x18\x80\xa0\xbd\n \x88\xe1\xfd\xb3\x06*\n-rw-rw-rw-\x1a#\n\nGoose2.dmp\x18\x85\xe3\xadM \xa9\xd6\xfd\xb3\x06*\n-rw-rw-rw-\x1a$\n\x0cHackBack.exe\x18\x9b\xd9\x12 \xa8\xe3\x99\xb3\x06*\n-rw-rw-rw-\x1a%\n\x0eHelloWorld.exe\x18\x80\x10 \xc3\xa9\xf4\xb2\x06*\n-rw-rw-rw-\x1a\x1b\n\x05Links\x10\x01 \xed\xe4\xfe\xab\x06*\ndr-xr-xr-x\x1a"\n\nLoader.dll\x18\xe6\xc1\x12 \xfa\xda\x99\xb3\x06*\n-rw-rw-rw-\x1a@\n\x0eLocal Settings \xd2\xe4\xfe\xab\x06*\nLrw-rw-rw-2\x1cC:\\Users\\Ronan\\AppData\\Local\x1a\x1d\n\x07Malware\x10\x01 \x89\xa4\xf5\xb2\x06*\ndrwxrwxrwx\x1a$\n\x0cMoneta64.exe\x18\x80\xa8\x08 \x81\x93\x83\xb3\x06*\n-rw-rw-rw-\x1a\x1b\n\x05Music\x10\x01 \xed\xe4\xfe\xab\x06*\ndr-xr-xr-x\x1a:\n\x0cMy Documents \xd2\xe4\xfe\xab\x06*\nLrw-rw-rw-2\x18C:\\Users\\Ronan\\Documents\x1a#\n\nNTUSER.DAT\x18\x80\x80\xd0\x01 \xfc\x99\xfd\xb3\x06*\n-rw-rw-rw-\x1aO\n7NTUSER.DAT{a2332f18-cdbf-11ec-8680-002248483d79}.TM.blf\x18\x80\x80\x04 \xe6\xe4\xfe\xab\x06*\n-rw-rw-rw-\x1at\n\\NTUSER.DAT{a2332f18-cdbf-11ec-8680-002248483d79}.TMContainer00000000000000000001.regtrans-ms\x18\x80\x80  \xd2\xe4\xfe\xab\x06*\n-rw-rw-rw-\x1at\n\\NTUSER.DAT{a2332f18-cdbf-11ec-8680-002248483d79}.TMContainer00000000000000000002.regtrans-ms\x18\x80\x80  \xd2\xe4\xfe\xab\x06*\n-rw-rw-rw-\x1a_\n\x07NetHood \xd2\xe4\xfe\xab\x06*\nLrw-rw-rw-2BC:\\Users\\Ronan\\AppData\\Roaming\\Microsoft\\Windows\\Network Shortcuts\x1a\x1e\n\x08OneDrive\x10\x01 \xcd\xe5\xfe\xab\x06*\ndr-xr-xr-x\x1a\x1e\n\x08Pictures\x10\x01 \x97\xe7\xf7\xb2\x06*\ndr-xr-xr-x\x1aa\n\tPrintHood \xd2\xe4\xfe\xab\x06*\nLrw-rw-rw-2BC:\\Users\\Ronan\\AppData\\Roaming\\Microsoft\\Windows\\Printer Shortcuts\x1a#\n\nPython.exe\x18\x80\xa8\xb1\x06 \xef\xe5\x92\xb3\x06*\n-rw-rw-rw-\x1aS\n\x06Recent \xd2\xe4\xfe\xab\x06*\nLrw-rw-rw-27C:\\Users\\Ronan\\AppData\\Roaming\\Microsoft\\Windows\\Recent\x1a!\n\x0bSaved Games\x10\x01 \xed\xe4\xfe\xab\x06*\ndr-xr-xr-x\x1a\x1e\n\x08Searches\x10\x01 \xcf\xe6\xfe\xab\x06*\ndr-xr-xr-x\x1aS\n\x06SendTo \xd2\xe4\xfe\xab\x06*\nLrw-rw-rw-27C:\\Users\\Ronan\\AppData\\Roaming\\Microsoft\\Windows\\SendTo\x1a"\n\nSigned.exe\x18\xb0\xb0\x13 \xa2\xe1\x99\xb3\x06*\n-rw-rw-rw-\x1a[\n\nStart Menu \xd2\xe4\xfe\xab\x06*\nLrw-rw-rw-2;C:\\Users\\Ronan\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\x1aY\n\tTemplates \xd2\xe4\xfe\xab\x06*\nLrw-rw-rw-2:C:\\Users\\Ronan\\AppData\\Roaming\\Microsoft\\Windows\\Templates\x1a\x1c\n\x06Videos\x10\x01 \xd2\xa3\x98\xac\x06*\ndr-xr-xr-x\x1a\x1f\n\x08cert.pfx\x18\xd4\x13 \x8c\x99\xf9\xb2\x06*\n-rw-rw-rw-\x1a$\n\x0bdotpeek.exe\x18\xe0\xc3\xc2\x19 \x93\xd5\xe9\xb2\x06*\n-rw-rw-rw-\x1a\x1c\n\x08evidence \x9d\xee\xb7\xb3\x06*\n-rw-rw-rw-\x1a \n\x08exec.exe\x18\xa2\x8e\x0f \xa7\xac\xfa\xb2\x06*\n-rw-rw-rw-\x1a \n\x08file.txt\x18\xe8\xb9\t \xdc\x83\x83\xb3\x06*\n-rw-rw-rw-\x1a\x1e\n\x08flag.txt\x183 \xed\xd4\xfd\xb3\x06*\n-rw-rw-rw-\x1a\x1f\n\x07log.txt\x18\xcf\x8a\x02 \xfb\x85\xf3\xb3\x06*\n-rw-rw-rw-\x1a\'\n\x0fntuser.dat.LOG1\x18\x80\xa0\x03 \xd2\xe4\xfe\xab\x06*\n-rw-rw-rw-\x1a\'\n\x0fntuser.dat.LOG2\x18\x80\x80\n \xd2\xe4\xfe\xab\x06*\n-rw-rw-rw-\x1a \n\nntuser.ini\x18\x14 \xd2\xe4\xfe\xab\x06*\n-rw-rw-rw-\x1a$\n\x0cpolyglot.exe\x18\xf6\x84\x13 \x9c\xd6\x99\xb3\x06*\n-rw-rw-rw-\x1a\x1a\n\x04rust\x10\x01 \xfc\xb0\xc7\xad\x06*\ndrwxrwxrwx\x1a\x1c\n\x06source\x10\x01 \xb9\x89\xf8\xb2\x06*\ndrwxrwxrwx\x1a\x1c\n\x04yeet\x18\xa5\x9c\x13 \x92\xd2\x99\xb3\x06*\n-rw-rw-rw-"\x03EDT(\xc0\x8f\xff\xff\xff\xff\xff\xff\xff\x01'
[+] Processing: http://10.0.0.101:80/assets/array.js?o=68257360
  [-] Decoding: gzip-words
  [!] Session Key: Unable to find a valid key for this session
[+] Processing: http://10.0.0.101:80/auth/authenticate/oauth/database/api.php?i=88894g737
  [-] Decoding: hex
  [-] Session Key: ccb90e9bb8db3ef5e121d7cbba944bf1a0e16fdf8a8a0d543b960ce7989cda33
  [-] Message Type: 0
[=] Message Data
b'\n\x15DESKTOP-DEQMME0\\Ronan'
[+] Processing: http://10.0.0.101:80/assets/backbone.js?g=50102x354
  [-] Decoding: hex
  [-] Session Key: ccb90e9bb8db3ef5e121d7cbba944bf1a0e16fdf8a8a0d543b960ce7989cda33
  [-] Message Type: 12
[=] Message Data
b'J\x07\x10\x80\xb0\x9d\xc2\xdf\x01'
[+] Processing: http://10.0.0.101:80/auth/samples.php?m=912l82j940
  [-] Decoding: gzip
  [!] Session Key: Unable to find a valid key for this session
[+] Processing: http://10.0.0.101:80/bundle/array.js?r=9565ah6438
  [-] Decoding: gzip-words
  [!] Session Key: Unable to find a valid key for this session
[+] Processing: http://10.0.0.101:80/oauth2callback/oauth/auth/samples.php?h=m31953704
  [-] Decoding: words
  [-] Session Key: ccb90e9bb8db3ef5e121d7cbba944bf1a0e16fdf8a8a0d543b960ce7989cda33
  [-] Message Type: 0
[=] Message Data
b'\n\x17C:\\Users\\Ronan\\flag.txt\x12\x04gzip\x18\x012O\x1f\x8b\x08\x00\x00\x00\x00\x00\x04\xff\x003\x00\xcc\xffuiuctf{GOOS3_CH4S3_ST0P_RUNN1NG_STR1NGS_0N_MY_CHAL}\x01\x00\x00\xff\xff\xe1\xd1\xe1\xcc3\x00\x00\x00@\x01J\x00'
[+] Processing: http://10.0.0.101:80/bootstrap.min.js?i=70189559
  [-] Decoding: b64
  [-] Session Key: ccb90e9bb8db3ef5e121d7cbba944bf1a0e16fdf8a8a0d543b960ce7989cda33
  [-] Message Type: 7
[=] Message Data
b'\n\x08flag.txtJ\x07\x10\x80\xb0\x9d\xc2\xdf\x01'
[+] Processing: http://10.0.0.101:80/samples.php?f=t28564447
  [-] Decoding: words
  [-] Session Key: ccb90e9bb8db3ef5e121d7cbba944bf1a0e16fdf8a8a0d543b960ce7989cda33
  [-] Message Type: 0
[=] Message Data
b'\n\x17C:\\Users\\Ronan\\flag.txt\x12\x04gzip\x18\x012O\x1f\x8b\x08\x00\x00\x00\x00\x00\x04\xff\x003\x00\xcc\xffuiuctf{GOOS3_CH4S3_ST0P_RUNN1NG_STR1NGS_0N_MY_CHAL}\x01\x00\x00\xff\xff\xe1\xd1\xe1\xcc3\x00\x00\x00@\x01J\x00'
[+] Processing: http://10.0.0.101:80/bundle/bootstrap.min.js?q=527119x64
  [-] Decoding: gzip-b64
  [-] Session Key: ccb90e9bb8db3ef5e121d7cbba944bf1a0e16fdf8a8a0d543b960ce7989cda33
  [-] Message Type: 7
[=] Message Data
b'\n\x08flag.txtJ\x07\x10\x80\xb0\x9d\xc2\xdf\x01'
[+] Processing: http://10.0.0.101:80/auth/database/oauth2callback/api.php?n=59z33056
  [-] Decoding: b64
  [-] Session Key: ccb90e9bb8db3ef5e121d7cbba944bf1a0e16fdf8a8a0d543b960ce7989cda33
  [-] Message Type: 0
[=] Message Data
b'\n\x17C:\\Users\\Ronan\\flag.txt\x12\x04gzip\x18\x012O\x1f\x8b\x08\x00\x00\x00\x00\x00\x04\xff\x003\x00\xcc\xffuiuctf{GOOS3_CH4S3_ST0P_RUNN1NG_STR1NGS_0N_MY_CHAL}\x01\x00\x00\xff\xff\xe1\xd1\xe1\xcc3\x00\x00\x00@\x01J\x00'
```

Flag: ***uiuctf{GOOS3_CH4S3_ST0P_RUNN1NG_STR1NGS_0N_MY_CHAL}***

I couldn't solve this in time because lack of knowledge but after the ctf, i try to redo this challenge and it helps me to know about SliverC2. Thanks UIUCTF organizer for such a cool challenge.


<!--more-->
