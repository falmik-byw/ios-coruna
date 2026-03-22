
void Reset(long param_1)

{
  *(undefined **)(param_1 + 0x30) = &DAT_00001024;
  *(code **)(param_1 + 0x38) = FUN_00003334;
  *(code **)(param_1 + 0x130) = FUN_0000340c;
  return;
}



undefined1  [16] FUN_000000b0(undefined8 param_1)

{
  bool in_CY;
  undefined8 uVar1;
  undefined1 auVar3 [16];
  undefined8 uVar2;
  
  CallSupervisor(0x80);
  uVar1 = param_1;
  uVar2 = 0;
  if (in_CY) {
    uVar1 = 0xffffffffffffffff;
    uVar2 = param_1;
  }
  auVar3._8_8_ = uVar2;
  auVar3._0_8_ = uVar1;
  return auVar3;
}



undefined1  [16] FUN_000000cc(undefined8 param_1)

{
  bool in_CY;
  undefined8 uVar1;
  undefined1 auVar3 [16];
  undefined8 uVar2;
  
  CallSupervisor(0x80);
  uVar1 = param_1;
  uVar2 = 0;
  if (in_CY) {
    uVar1 = 0xffffffffffffffff;
    uVar2 = param_1;
  }
  auVar3._8_8_ = uVar2;
  auVar3._0_8_ = uVar1;
  return auVar3;
}



undefined1  [16] FUN_0000013c(undefined8 param_1)

{
  bool in_CY;
  undefined8 uVar1;
  undefined1 auVar3 [16];
  undefined8 uVar2;
  
  CallSupervisor(0x80);
  uVar1 = param_1;
  uVar2 = 0;
  if (in_CY) {
    uVar1 = 0xffffffffffffffff;
    uVar2 = param_1;
  }
  auVar3._8_8_ = uVar2;
  auVar3._0_8_ = uVar1;
  return auVar3;
}



undefined8 FUN_00003334(undefined8 param_1,long param_2,long param_3,long *param_4)

{
  int iVar1;
  long lVar2;
  long lVar3;
  undefined8 uVar4;
  long *plVar5;
  ulong uVar6;
  
  uVar4 = 0xad001;
  if ((((param_3 != 0) && (param_4 != (long *)0x0)) && (param_2 != 0)) &&
     ((lVar3 = *(long *)(param_2 + 0x38), lVar3 != 0 && (*(long *)(param_2 + 0x48) != 0)))) {
    *param_4 = 0;
    lVar2 = *(long *)(param_2 + 0x30);
    uVar4 = 0x12001;
    if (*(int *)(lVar2 + 0xc) != 0) {
      uVar6 = 0;
      plVar5 = (long *)(lVar3 + 8);
      do {
        if ((*(byte *)((long)plVar5 + -4) & 0xe1) == 1) {
          iVar1 = FUN_00003840(param_3,*(long *)(param_2 + 0x48) + (ulong)*(uint *)(plVar5 + -1));
          if (iVar1 == 0) {
            *param_4 = (*(long *)(param_2 + 0x60) - *(long *)(param_2 + 0x50)) + *plVar5;
            return 0;
          }
          lVar2 = *(long *)(param_2 + 0x30);
        }
        uVar6 = uVar6 + 1;
        plVar5 = plVar5 + 2;
      } while (uVar6 < *(uint *)(lVar2 + 0xc));
    }
  }
  return uVar4;
}



undefined8 FUN_0000340c(long param_1,long *param_2)

{
  long lVar1;
  long lVar2;
  byte bVar3;
  int iVar4;
  long lVar5;
  code *pcVar6;
  long lVar7;
  uint uVar8;
  undefined8 uVar9;
  int *piVar10;
  int *piVar11;
  int *piVar12;
  
  bVar3 = *(byte *)((long)param_2 + 0xac);
  if (-1 < (char)bVar3) {
    if ((((bVar3 >> 4 & 1) == 0) && ((bVar3 >> 1 & 1) != 0)) &&
       (lVar5 = *param_2, *(int *)(lVar5 + 0x10) != 0)) {
      uVar8 = 0;
      lVar1 = param_2[10];
      lVar2 = param_2[0xb];
      piVar10 = (int *)(param_2[0xd] + 0x20);
      do {
        if (*piVar10 == 0x19) {
          piVar11 = piVar10 + 0x12;
          piVar12 = piVar11 + (ulong)(uint)piVar10[0x10] * 0x14;
          if (piVar11 < piVar12) {
            do {
              if (((char)piVar11[0x10] == '\n') && ((int)(*(ulong *)(piVar11 + 10) >> 3) != 0)) {
                lVar7 = *(long *)(piVar11 + 8);
                lVar5 = (*(ulong *)(piVar11 + 10) >> 3 & 0xffffffff) << 3;
                do {
                  pcVar6 = *(code **)((lVar2 - lVar1) + lVar7 + -8 + lVar5);
                  if (pcVar6 < (code *)param_2[0xb] ||
                      (code *)param_2[0xb] + *(uint *)(param_2 + 0x15) <= pcVar6) {
                    return 0x12009;
                  }
                  (*pcVar6)();
                  lVar5 = lVar5 + -8;
                } while (lVar5 != 0);
              }
              piVar11 = piVar11 + 0x14;
            } while (piVar11 < piVar12);
            lVar5 = *param_2;
          }
        }
        piVar10 = (int *)((long)piVar10 + (ulong)(uint)piVar10[1]);
        uVar8 = uVar8 + 1;
      } while (uVar8 < *(uint *)(lVar5 + 0x10));
    }
    if (param_2[0xf] != 0) {
      (*(code *)param_2[0x13])(0,param_2[0xb]);
    }
    uVar9 = 0x1400b;
    iVar4 = FUN_00004648(param_1,param_2[0xb],(int)param_2[0x15],3);
    if (iVar4 != 0) goto LAB_000035e8;
    FUN_000037b4(param_2[0xb],0,(int)param_2[0x15]);
    if (param_2[0xf] == 0) {
      uVar8 = *(uint *)(param_2 + 0x15);
      if (*(char *)(param_1 + 0x5c5) == '\0') {
        if (*(code **)(param_1 + 0xb0) == Reset) goto LAB_000035e4;
        iVar4 = (**(code **)(param_1 + 0xb0))(param_1,param_2[0xb]);
      }
      else {
        lVar5 = 0;
        if ((uVar8 & 0x3fff) != 0) {
          lVar5 = 0x4000 - ((ulong)uVar8 & 0x3fff);
        }
        iVar4 = FUN_00004648(param_1,param_2[0xb],lVar5 + (ulong)uVar8,
                             *(undefined4 *)(param_1 + 0x5c8));
      }
      if (iVar4 != 0) {
        uVar9 = 0x1400c;
        goto LAB_000035e8;
      }
    }
    else if ((*(char *)(param_1 + 0x5c5) != '\0') &&
            (iVar4 = FUN_00004648(param_1,param_2[0xb],(int)param_2[0x15],
                                  *(undefined4 *)(param_1 + 0x5c8)), iVar4 != 0)) goto LAB_000035e8;
  }
LAB_000035e4:
  uVar9 = 0;
LAB_000035e8:
  FUN_000037b4(param_2,0,0x120);
  FUN_00004514(param_1,param_2,0x120);
  return uVar9;
}



void FUN_00003628(long param_1,long param_2,ulong param_3)

{
  undefined8 local_30;
  
  for (local_30 = 0; local_30 < param_3; local_30 = local_30 + 1) {
    *(undefined1 *)(param_1 + local_30) = *(undefined1 *)(param_2 + local_30);
  }
  return;
}



long FUN_00003694(long param_1,long param_2,long param_3,ulong param_4)

{
  bool bVar1;
  char cVar2;
  undefined8 local_40;
  undefined8 local_30;
  undefined8 local_8;
  
  local_30 = 0;
  do {
    if (param_2 - param_4 <= local_30) {
      cVar2 = '\x02';
LAB_00003794:
      if (cVar2 != '\x01') {
        local_8 = 0;
      }
      return local_8;
    }
    bVar1 = true;
    for (local_40 = 0; local_40 < param_4; local_40 = local_40 + 4) {
      if (*(int *)(param_1 + local_30 + local_40) != *(int *)(param_3 + local_40)) {
        bVar1 = false;
        break;
      }
    }
    if (bVar1) {
      local_8 = param_1 + local_30;
      cVar2 = '\x01';
      goto LAB_00003794;
    }
    local_30 = local_30 + 4;
  } while( true );
}



void FUN_000037b4(long param_1,char param_2,ulong param_3)

{
  undefined8 local_20;
  
  for (local_20 = 0; local_20 < param_3; local_20 = local_20 + 1) {
    *(char *)(param_1 + local_20) = param_2 + '\x01';
  }
  for (local_20 = 0; local_20 < param_3; local_20 = local_20 + 1) {
    *(char *)(param_1 + local_20) = param_2;
  }
  return;
}



undefined4 FUN_00003840(char *param_1,char *param_2)

{
  char cVar1;
  char *local_18;
  char *local_10;
  
  local_18 = param_2;
  local_10 = param_1;
  do {
    cVar1 = *local_18;
    if (*local_10 != cVar1) {
      return 1;
    }
    local_18 = local_18 + 1;
    local_10 = local_10 + 1;
  } while (cVar1 != '\0');
  return 0;
}



undefined4 FUN_000038b8(long param_1,long param_2,ulong param_3)

{
  ulong local_28;
  
  local_28 = 0;
  while( true ) {
    if (param_3 <= local_28) {
      return 0;
    }
    if (*(char *)(param_2 + local_28) != *(char *)(param_1 + local_28)) break;
    if (*(char *)(param_2 + local_28) == '\0') {
      return 0;
    }
    local_28 = local_28 + 1;
  }
  return 1;
}



int FUN_00003964(int param_1,int param_2)

{
  int iVar1;
  
  if (param_1 < param_2) {
    iVar1 = 0;
  }
  else {
    iVar1 = 0;
    do {
      param_1 = param_1 - param_2;
      iVar1 = iVar1 + 1;
    } while (param_2 <= param_1);
  }
  return iVar1;
}



int FUN_00003990(int param_1,int param_2)

{
  return param_1 * param_2;
}



void FUN_00003998(undefined4 param_1,undefined4 *param_2,undefined8 param_3,undefined8 *param_4)

{
  if ((param_2 != (undefined4 *)0x0) && (param_4 != (undefined8 *)0x0)) {
    *param_2 = param_1;
    *param_4 = param_3;
  }
  return;
}



ulong FUN_000039ac(int param_1,long param_2,undefined8 param_3,undefined8 param_4)

{
  bool bVar1;
  byte *pbVar2;
  uint uVar3;
  byte bVar4;
  ulong uVar5;
  byte *pbVar7;
  ulong uVar8;
  ulong uVar9;
  ulong uVar10;
  byte *pbVar11;
  byte *pbVar12;
  undefined4 uVar13;
  ulong uVar14;
  ulong uVar15;
  ulong uVar16;
  long lVar17;
  long local_90;
  uint local_84;
  byte *local_80;
  uint local_74;
  uint *puVar6;
  
  if (param_1 == 1) {
    pbVar12 = (byte *)(*(long *)(param_2 + 0x68) +
                      (ulong)*(uint *)(*(long *)(param_2 + 0x20) + 0x20));
    puVar6 = (uint *)(*(long *)(param_2 + 0x20) + 0x24);
  }
  else {
    if (param_1 != 0) {
      return 0x910008;
    }
    pbVar12 = (byte *)(*(long *)(param_2 + 0x68) +
                      (ulong)*(uint *)(*(long *)(param_2 + 0x20) + 0x10));
    puVar6 = (uint *)(*(long *)(param_2 + 0x20) + 0x14);
  }
  uVar5 = (ulong)*puVar6;
  if (*puVar6 != 0) {
    uVar15 = 0;
    local_90 = 0;
    local_84 = 0;
    uVar14 = 0;
    uVar16 = 0;
    local_80 = (byte *)0x0;
    lVar17 = 0;
    pbVar2 = pbVar12 + uVar5;
    local_74 = 1;
    do {
      pbVar11 = pbVar12 + 1;
      bVar4 = *pbVar12;
      pbVar12 = pbVar11;
      if ((bVar4 >> 4) - 1 < 0xd) {
        uVar3 = bVar4 & 0xf;
        uVar5 = (ulong)uVar3;
        uVar13 = (undefined4)uVar14;
        switch((uint)(bVar4 >> 4)) {
        case 1:
          uVar14 = uVar5;
          break;
        case 2:
          uVar14 = 0;
          uVar5 = 0;
          pbVar7 = pbVar11;
          do {
            if (pbVar2 <= pbVar7) {
              uVar14 = 0;
              pbVar12 = pbVar11;
              break;
            }
            pbVar12 = pbVar7 + 1;
            bVar4 = *pbVar7;
            uVar10 = ((ulong)bVar4 & 0x7f) << (uVar5 & 0x3f);
            if (0x3f < (uint)uVar5) {
              uVar10 = 0;
            }
            uVar14 = uVar10 | uVar14;
            uVar5 = (ulong)((uint)uVar5 + 7);
            pbVar7 = pbVar12;
          } while ((char)bVar4 < '\0');
          break;
        case 3:
          uVar3 = 0;
          if ((bVar4 & 0xf) != 0) {
            uVar3 = (int)(char)bVar4 | 0xfffffff0;
          }
          uVar14 = (ulong)uVar3;
          break;
        case 4:
          pbVar7 = pbVar11;
          do {
            local_84 = uVar3;
            if (pbVar7 == pbVar2) {
              local_80 = (byte *)0x0;
              pbVar12 = pbVar11;
              break;
            }
            bVar4 = *pbVar7;
            pbVar12 = pbVar7 + 1;
            pbVar7 = pbVar7 + 1;
            local_80 = pbVar11;
          } while (bVar4 != 0);
          break;
        case 5:
          local_74 = uVar3;
          break;
        case 6:
          uVar16 = 0;
          uVar5 = 0;
          pbVar7 = pbVar11;
          do {
            if (pbVar2 <= pbVar7) {
              uVar16 = 0;
              pbVar12 = pbVar11;
              goto LAB_00003d9c;
            }
            pbVar12 = pbVar7 + 1;
            bVar4 = *pbVar7;
            uVar10 = ((ulong)bVar4 & 0x7f) << (uVar5 & 0x3f);
            if (0x3f < (uint)uVar5) {
              uVar10 = 0;
            }
            uVar16 = uVar10 | uVar16;
            uVar5 = (ulong)((uint)uVar5 + 7);
            pbVar7 = pbVar12;
          } while ((char)bVar4 < '\0');
          if ((bVar4 & 0x40) != 0) {
            uVar16 = 0xffffffffffffffff;
          }
          break;
        case 7:
          lVar17 = FUN_00004ea8(uVar5,param_2);
          if (lVar17 == 0) {
            return 0x910009;
          }
          uVar5 = 0;
          uVar10 = 0;
          pbVar7 = pbVar11;
          do {
            if (pbVar2 <= pbVar7) {
              uVar5 = 0;
              pbVar12 = pbVar11;
              break;
            }
            pbVar12 = pbVar7 + 1;
            bVar4 = *pbVar7;
            uVar8 = ((ulong)bVar4 & 0x7f) << (uVar10 & 0x3f);
            if (0x3f < (uint)uVar10) {
              uVar8 = 0;
            }
            uVar5 = uVar8 | uVar5;
            uVar10 = (ulong)((uint)uVar10 + 7);
            pbVar7 = pbVar12;
          } while ((char)bVar4 < '\0');
          lVar17 = lVar17 + uVar5;
          break;
        case 8:
          uVar5 = 0;
          uVar10 = 0;
          pbVar7 = pbVar11;
          do {
            if (pbVar2 <= pbVar7) {
              uVar5 = 0;
              pbVar12 = pbVar11;
              break;
            }
            pbVar12 = pbVar7 + 1;
            bVar4 = *pbVar7;
            uVar8 = ((ulong)bVar4 & 0x7f) << (uVar10 & 0x3f);
            if (0x3f < (uint)uVar10) {
              uVar8 = 0;
            }
            uVar5 = uVar8 | uVar5;
            uVar10 = (ulong)((uint)uVar10 + 7);
            pbVar7 = pbVar12;
          } while ((char)bVar4 < '\0');
          lVar17 = lVar17 + uVar5;
          break;
        case 9:
          uVar5 = FUN_00004f04(lVar17,local_80,local_84,local_74,uVar16,param_3,param_4,param_2,
                               uVar13);
          if ((int)uVar5 != 0) {
            return uVar5;
          }
          lVar17 = lVar17 + 8;
          break;
        case 10:
          uVar5 = FUN_00004f04(lVar17,local_80,local_84,local_74,uVar16,param_3,param_4,param_2,
                               uVar13);
          if ((int)uVar5 != 0) {
            return uVar5;
          }
          uVar5 = 0;
          uVar10 = 0;
          pbVar7 = pbVar11;
          do {
            if (pbVar2 <= pbVar7) {
              uVar5 = 0;
              pbVar12 = pbVar11;
              break;
            }
            pbVar12 = pbVar7 + 1;
            bVar4 = *pbVar7;
            uVar8 = ((ulong)bVar4 & 0x7f) << (uVar10 & 0x3f);
            if (0x3f < (uint)uVar10) {
              uVar8 = 0;
            }
            uVar5 = uVar8 | uVar5;
            uVar10 = (ulong)((uint)uVar10 + 7);
            pbVar7 = pbVar12;
          } while ((char)bVar4 < '\0');
          lVar17 = uVar5 + lVar17 + 8;
          break;
        case 0xb:
          uVar10 = FUN_00004f04(lVar17,local_80,local_84,local_74,uVar16,param_3,param_4,param_2,
                                uVar13);
          if ((int)uVar10 != 0) {
            return uVar10;
          }
          uVar5 = FUN_00003990(uVar5,8);
          lVar17 = lVar17 + (uVar5 & 0xffffffff) + 8;
          break;
        case 0xc:
          uVar10 = 0;
          uVar5 = 0;
          do {
            if (pbVar2 <= pbVar12) {
              uVar10 = 0;
              pbVar7 = pbVar11;
              break;
            }
            pbVar7 = pbVar12 + 1;
            bVar4 = *pbVar12;
            uVar8 = ((ulong)bVar4 & 0x7f) << (uVar5 & 0x3f);
            if (0x3f < (uint)uVar5) {
              uVar8 = 0;
            }
            uVar10 = uVar8 | uVar10;
            uVar5 = (ulong)((uint)uVar5 + 7);
            pbVar12 = pbVar7;
          } while ((char)bVar4 < '\0');
          uVar5 = 0;
          uVar8 = 0;
          pbVar11 = pbVar7;
          do {
            if (pbVar2 <= pbVar11) {
              uVar5 = 0;
              pbVar12 = pbVar7;
              break;
            }
            pbVar12 = pbVar11 + 1;
            bVar4 = *pbVar11;
            uVar9 = ((ulong)bVar4 & 0x7f) << (uVar8 & 0x3f);
            if (0x3f < (uint)uVar8) {
              uVar9 = 0;
            }
            uVar5 = uVar9 | uVar5;
            uVar8 = (ulong)((uint)uVar8 + 7);
            pbVar11 = pbVar12;
          } while ((char)bVar4 < '\0');
          if (uVar10 != 0) {
            uVar8 = 1;
            do {
              uVar9 = FUN_00004f04(lVar17,local_80,local_84,local_74,uVar16,param_3,param_4,param_2,
                                   uVar13);
              if ((int)uVar9 != 0) {
                return uVar9;
              }
              lVar17 = lVar17 + uVar5 + 8;
              bVar1 = uVar8 < uVar10;
              uVar8 = (ulong)((int)uVar8 + 1);
            } while (bVar1);
          }
          uVar15 = uVar15 & 0xffffffff;
          break;
        case 0xd:
          if (uVar3 == 1) {
            if (local_90 == 0) {
              return 0x910018;
            }
            uVar5 = FUN_00004da0(param_2,lVar17,local_90,uVar15);
            if ((int)uVar5 != 0) {
              return uVar5;
            }
          }
          else {
            if ((bVar4 & 0xf) != 0) {
              return 0x91000d;
            }
            uVar10 = 0;
            pbVar7 = pbVar11;
            do {
              if (pbVar2 <= pbVar7) {
                uVar10 = 0;
                pbVar12 = pbVar11;
                goto joined_r0x00003eb4;
              }
              pbVar12 = pbVar7 + 1;
              bVar4 = *pbVar7;
              uVar8 = ((ulong)bVar4 & 0x7f) << (uVar5 & 0x3f);
              if (0x3f < (uint)uVar5) {
                uVar8 = 0;
              }
              uVar10 = uVar8 | uVar10;
              uVar5 = (ulong)((uint)uVar5 + 7);
              pbVar7 = pbVar12;
            } while ((char)bVar4 < '\0');
            if (uVar10 >> 0x10 != 0) {
              return 0x91000f;
            }
joined_r0x00003eb4:
            if (local_90 != 0) {
              FUN_00004514(param_4,local_90,(uVar15 & 0xffffffff) << 3);
              uVar15 = 0;
            }
            if (uVar10 == 0) {
              local_90 = 0;
              lVar17 = local_90;
            }
            else {
              local_90 = FUN_0000454c(param_4,uVar10 << 3,0);
              if (local_90 == 0) {
                return 0xad009;
              }
              FUN_000037b4(local_90,0,uVar10 << 3);
              uVar15 = uVar10;
              lVar17 = local_90;
            }
          }
        }
      }
LAB_00003d9c:
    } while (pbVar12 < pbVar2);
    if (local_90 != 0) {
      FUN_00004514(param_4,local_90,(uVar15 & 0xffffffff) << 3);
    }
    uVar5 = 0;
  }
  return uVar5;
}



ulong FUN_00003f64(long param_1,long param_2)

{
  int *piVar1;
  undefined *puVar2;
  bool bVar3;
  code *pcVar4;
  int iVar5;
  ulong uVar6;
  int *piVar7;
  uint uVar8;
  undefined4 uVar9;
  int *piVar10;
  long lVar11;
  long lVar12;
  uint uVar13;
  undefined8 uVar14;
  long lVar15;
  long lVar16;
  undefined8 local_98 [2];
  undefined8 local_88;
  undefined8 local_80;
  code *local_78;
  
  if (param_1 == 0) {
    return 0xad001;
  }
  if (param_2 == 0) {
    return 0xad001;
  }
  if (*(char *)(param_2 + 0x5c7) == '\0') {
    return 0;
  }
  lVar12 = *(long *)(param_2 + 0x5d8);
  if (lVar12 == 0) {
    return 0xad001;
  }
  if (*(long *)(param_2 + 0x5d0) == 0) {
    return 0xad001;
  }
  uVar8 = *(uint *)(param_1 + 0xa8);
  lVar15 = *(long *)(param_1 + 0x58);
  local_98[0] = 0;
  uVar6 = FUN_0000566c(param_2,s__System_Library_Frameworks_JavaS_00005fd3,
                       s_JSEvaluateScript_00006016,local_98);
  pcVar4 = DAT_00005dc0;
  if ((int)uVar6 != 0) {
    return uVar6;
  }
  lVar16 = 0;
  uVar13 = 0;
  lVar15 = lVar15 - lVar12;
  local_88 = DAT_00005db4;
  local_80 = CONCAT44(local_80._4_4_,DAT_00005dbc);
  do {
    lVar12 = FUN_00005b6c(local_98[0]);
    piVar1 = (int *)(lVar12 + 0xc00000);
    piVar7 = (int *)FUN_00005b6c(local_98[0]);
    if (piVar7 < piVar1 && piVar7 != (int *)0x0) {
      while (piVar7 = (int *)FUN_00003694(piVar7,(long)piVar1 - (long)piVar7,
                                          (long)&local_88 + lVar16 * 4,4), piVar7 != (int *)0x0) {
        local_78 = pcVar4;
        lVar12 = FUN_00003694(piVar7,0x1000,&local_78,8);
        if (lVar12 != 0) {
          if (lVar16 == 0) {
            local_78 = Reset;
            uVar6 = FUN_0000566c(param_2,s__usr_lib_system_libsystem_c_dyli_00005f01,
                                 s_sigaction_00006027,&local_78);
            if ((int)uVar6 != 0) {
              return uVar6;
            }
            lVar16 = FUN_0000013c(0,0x8000,3,&DAT_00001002,0,0);
            if (lVar16 == -1) {
              return 0x15001;
            }
            iVar5 = *(int *)(param_2 + 0xe0);
            if (((iVar5 == -0x789a1216) || (iVar5 == -0x25cc27c3)) || (iVar5 == 0x2876f5b5)) {
              uVar14 = 0xb;
              bVar3 = true;
LAB_00004370:
              pcVar4 = local_78;
              FUN_000037b4(&local_88,0,0x10);
              local_88 = FUN_00005ba0(FUN_00005714,0);
              local_80 = DAT_00005dc8;
              iVar5 = (*pcVar4)(uVar14,&local_88,local_98);
              if (iVar5 == 0) {
                puVar2 = (undefined *)0x1339;
                if (bVar3) {
                  lVar11 = 0;
                }
                else {
                  puVar2 = &DAT_00001337;
                  lVar11 = *(long *)(param_2 + 0x5d0);
                }
                *(long *)(lVar16 + 0x330) = lVar12;
                *(undefined8 *)(lVar16 + 0x338) = *(undefined8 *)(param_2 + 0x5d0);
                if (uVar8 == 0) goto LAB_000044c0;
                uVar6 = 0;
                lVar12 = *(long *)(param_2 + 0x5d0);
                goto LAB_00004470;
              }
              uVar8 = 0x8002;
            }
            else {
              iVar5 = FUN_000000cc(lVar16 + 0x4000,0x4000,0);
              if (iVar5 == 0) {
                bVar3 = false;
                uVar14 = 10;
                goto LAB_00004370;
              }
              uVar8 = 0x8001;
            }
            uVar8 = (uVar8 | 0xfff60000) + 0xad001;
            goto LAB_00004504;
          }
          uVar6 = 0;
          piVar10 = piVar7;
          do {
            if (piVar10[-1] == -0x2efebc01) {
              if (*piVar10 == -0x56fda80a) {
                if ((piVar7[2] & 0xffc001e0U) == 0xb90001e0) {
                  uVar13 = (uint)piVar7[2] >> 8 & 0x3ffc;
                  uVar9 = 3;
LAB_000041c8:
                  if (uVar8 == 0) {
                    return 0;
                  }
                  uVar6 = 0;
                  lVar16 = *(long *)(param_2 + 0x5d0);
                  do {
                    iVar5 = *(int *)(*(long *)(param_2 + 0x5d8) + lVar15 + uVar6);
                    piVar7 = (int *)(lVar16 + lVar15 + uVar6);
                    if (iVar5 != *piVar7) {
                      switch(uVar9) {
                      case 1:
                        FUN_00005ce8(lVar12,iVar5);
                        break;
                      case 2:
                        FUN_00005d4c(lVar12,iVar5,piVar7,uVar13);
                        break;
                      case 3:
                        FUN_00005d74(lVar12,iVar5,piVar7,uVar13);
                        break;
                      case 4:
                        FUN_00005d0c(lVar12,iVar5,piVar7,uVar13);
                      }
                      lVar16 = *(long *)(param_2 + 0x5d0);
                      if (iVar5 != *(int *)(lVar16 + lVar15 + uVar6)) {
                        return 0x15005;
                      }
                    }
                    uVar6 = uVar6 + 4;
                    if (uVar8 <= uVar6) {
                      return 0;
                    }
                  } while( true );
                }
                break;
              }
              if (*piVar10 == -0x56fea008) {
                if ((piVar7[2] & 0xffc001e0U) == 0xb90001e0) {
                  uVar13 = (uint)piVar7[2] >> 8 & 0x3ffc;
                  uVar9 = 2;
                  goto LAB_000041c8;
                }
                break;
              }
            }
            else if (piVar10[-1] == -0x2efefc01) {
              if (*piVar10 == -0x56fea80a) {
                uVar13 = 0;
                uVar9 = 1;
                goto LAB_000041c8;
              }
              if (*piVar10 == -0x56fdb00c) {
                if ((piVar7[2] & 0xffc001e0U) == 0xb90001e0) {
                  uVar13 = (uint)piVar7[2] >> 8 & 0x3ffc;
                  uVar9 = 4;
                  goto LAB_000041c8;
                }
                break;
              }
            }
            uVar6 = uVar6 + 4;
            piVar10 = piVar10 + -1;
          } while (uVar6 < 0xed);
        }
        piVar7 = piVar7 + 1;
        if ((piVar1 <= piVar7) || (piVar7 == (int *)0x0)) break;
      }
      uVar13 = 0x15004;
    }
    lVar16 = lVar16 + 1;
    if (lVar16 == 3) {
      uVar8 = 0x15006;
      if (uVar13 != 0) {
        uVar8 = uVar13;
      }
      return (ulong)uVar8;
    }
  } while( true );
LAB_00004470:
  do {
    iVar5 = *(int *)(*(long *)(param_2 + 0x5d8) + lVar15 + uVar6);
    if (iVar5 != *(int *)(lVar12 + lVar15 + uVar6)) {
      FUN_00003998(iVar5,lVar11 + lVar15 + uVar6,puVar2,lVar16);
      lVar12 = *(long *)(param_2 + 0x5d0);
      if (iVar5 != *(int *)(lVar12 + lVar15 + uVar6)) {
        uVar8 = 0x15005;
        goto LAB_000044e0;
      }
    }
    uVar6 = uVar6 + 4;
  } while (uVar6 < uVar8);
LAB_000044c0:
  uVar8 = 0;
LAB_000044e0:
  iVar5 = (*pcVar4)(uVar14,local_98,0);
  if (iVar5 != 0) {
    uVar8 = 0x15003;
  }
LAB_00004504:
  FUN_000000b0(lVar16,0x8000);
  return (ulong)uVar8;
}



void FUN_00004514(long param_1,undefined8 param_2,ulong param_3)

{
  long lVar1;
  
  if (*(char *)(param_1 + 0x5c5) != '\0') {
    lVar1 = 0;
    if ((param_3 & 0x3fff) != 0) {
      lVar1 = 0x4000 - (param_3 & 0x3fff);
    }
    FUN_00004648(param_1,param_2,lVar1 + param_3,*(undefined4 *)(param_1 + 0x5c8));
    return;
  }
  if (*(code **)(param_1 + 0xb0) != Reset) {
                    /* WARNING: Could not recover jumptable at 0x00004544. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)(param_1 + 0xb0))();
    return;
  }
  return;
}



ulong FUN_0000454c(long param_1,ulong param_2,ulong param_3)

{
  long lVar1;
  int iVar2;
  ulong uVar3;
  ulong uVar4;
  
  uVar4 = param_2;
  if ((*(char *)(param_1 + 0x5c2) == '\0') &&
     (((param_3 & 1) != 0 || (*(char *)(param_1 + 0x5c5) != '\0')))) {
    uVar4 = param_2 + 0x4000;
  }
  while (uVar3 = (**(code **)(param_1 + 0x28))(param_1,uVar4), uVar3 == 0) {
    if ((*(code **)(param_1 + 0x128) == Reset) ||
       (iVar2 = (**(code **)(param_1 + 0x128))(param_1,uVar4), iVar2 != 0)) {
      return -(param_3 & 1);
    }
  }
  if (*(char *)(param_1 + 0x5c2) != '\0') {
    return uVar3;
  }
  if ((((param_3 & 1) != 0) || (*(char *)(param_1 + 0x5c5) != '\0')) && ((uVar3 & 0x3fff) != 0)) {
    uVar3 = uVar3 + 0x4000 & 0xffffffffffffc000;
  }
  if (*(char *)(param_1 + 0x5c5) == '\0') {
    return uVar3;
  }
  lVar1 = 0;
  if ((param_2 & 0x3fff) != 0) {
    lVar1 = 0x4000 - (param_2 & 0x3fff);
  }
  iVar2 = FUN_00004648(param_1,uVar3,lVar1 + param_2,3);
  if (iVar2 == 0) {
    return uVar3;
  }
  return -(param_3 & 1);
}



undefined8 FUN_00004648(long param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  undefined8 uVar1;
  
  if (*(char *)(param_1 + 0x5c5) == '\0') {
    if ((((*(char *)(param_1 + 0x5c1) == '\0') || (*(char *)(param_1 + 0x5c4) != '\0')) ||
        (*(char *)(param_1 + 0x5c7) != '\0')) || (((uint)param_4 >> 2 & 1) != 0)) {
      return 0;
    }
    param_4 = 3;
  }
  uVar1 = FUN_000000cc(param_2,param_3,param_4);
  return uVar1;
}



undefined8 FUN_0000468c(long *param_1,ulong param_2,long *param_3)

{
  long lVar1;
  long lVar2;
  int iVar3;
  undefined8 uVar4;
  ulong uVar5;
  uint uVar6;
  int *piVar7;
  
  uVar4 = 0xad001;
  if ((param_1 != (long *)0x0) && (param_3 != (long *)0x0)) {
    if (*(int *)(*param_1 + 0x10) != 0) {
      uVar6 = 0;
      lVar1 = param_1[10];
      lVar2 = param_1[0xb];
      piVar7 = (int *)(param_1[0xd] + 0x20);
      do {
        if ((((*piVar7 == 0x19) && (*(long *)(piVar7 + 0xc) != 0)) &&
            (iVar3 = FUN_000038b8(piVar7 + 2,s___PAGEZERO_00005dd4,0xb), iVar3 != 0)) &&
           ((*(ulong *)(piVar7 + 10) <= param_2 &&
            (uVar5 = param_2 - *(ulong *)(piVar7 + 10), uVar5 < *(ulong *)(piVar7 + 0xc))))) {
          *param_3 = (lVar2 - lVar1) + uVar5 + *(long *)(piVar7 + 6);
          return 0;
        }
        piVar7 = (int *)((long)piVar7 + (ulong)(uint)piVar7[1]);
        uVar6 = uVar6 + 1;
      } while (uVar6 < *(uint *)(*param_1 + 0x10));
    }
    uVar4 = 0xad011;
  }
  return uVar4;
}



undefined8
FUN_00004784(long param_1,long param_2,undefined8 *param_3,undefined8 *param_4,uint param_5)

{
  uint uVar1;
  uint uVar2;
  bool bVar3;
  int iVar4;
  long lVar5;
  undefined8 uVar6;
  uint uVar7;
  undefined8 local_48;
  
  if (((((param_1 != 0) && (param_2 != 0)) && (param_3 != (undefined8 *)0x0)) &&
      ((param_4 != (undefined8 *)0x0 && (param_5 != 0)))) && (param_5 != 0xfffffffe)) {
    if (param_5 == 0xffffffff) {
      lVar5 = -5;
    }
    else if ((((int)param_5 < 1) || (*(uint *)(param_2 + 0x200) < param_5)) ||
            (lVar5 = *(long *)(param_2 + (ulong)(param_5 - 1) * 8), lVar5 == 0)) goto LAB_00004808;
    uVar6 = FUN_00004930(lVar5,param_1,param_3,param_4);
    if ((int)uVar6 == 0) {
      return uVar6;
    }
  }
LAB_00004808:
  lVar5 = (*(code *)*param_3)(s__usr_lib_system_libcache_dylib_00005e62,0x12);
  if (lVar5 != 0) {
    iVar4 = FUN_00004930(lVar5,param_1,param_3,&local_48);
    (*(code *)param_3[3])(lVar5);
    if (iVar4 == 0) goto LAB_00004910;
  }
  uVar1 = *(uint *)(param_2 + 0x204);
  uVar2 = *(uint *)(param_2 + 0x200);
  uVar7 = uVar1;
  if (uVar2 <= uVar1) {
    uVar7 = 0;
  }
  if (uVar7 < uVar2) {
    bVar3 = uVar1 < uVar2;
    do {
      lVar5 = *(long *)(param_2 + (ulong)uVar7 * 8);
      if ((lVar5 != 0) && (iVar4 = FUN_00004930(lVar5,param_1,param_3,&local_48), iVar4 == 0)) {
        *(uint *)(param_2 + 0x204) = uVar7;
        goto LAB_00004910;
      }
      if (bVar3) {
        uVar7 = (uint)(uVar7 == 0);
        *(undefined4 *)(param_2 + 0x204) = 0;
      }
      else {
        uVar7 = uVar7 + 1;
      }
      bVar3 = false;
    } while (uVar7 < *(uint *)(param_2 + 0x200));
  }
  iVar4 = FUN_00003840(param_1,s_dyld_stub_binder_00005e81);
  if (iVar4 == 0) {
    local_48 = 0xdeadbeef;
  }
  else {
    iVar4 = FUN_00003840(param_1,s___objc_empty_vtable_00005e92);
    if ((iVar4 != 0) && (iVar4 = FUN_00003840(param_1,s__objc_readClassPair_00005ea6), iVar4 != 0))
    {
      return 0x910006;
    }
    local_48 = 0;
  }
LAB_00004910:
  *param_4 = local_48;
  return 0;
}



undefined8 FUN_00004930(undefined8 param_1,char *param_2,undefined8 *param_3,long *param_4)

{
  int iVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  
  (*(code *)param_3[4])();
  if ((*(char *)(param_3 + 0xb8) == '\0') ||
     (iVar1 = FUN_00003840(param_2,s__pthread_create_00005eba), iVar1 != 0)) {
    if (*param_2 == '_') {
      param_2 = param_2 + 1;
    }
    (*(code *)param_3[1])(param_1,param_2);
    lVar2 = FUN_00005b6c();
    (*(code *)param_3[4])();
    *param_4 = lVar2;
    if (lVar2 != 0) {
      return 0;
    }
  }
  else {
    lVar2 = DAT_00005ac8;
    lVar4 = DAT_00005ad0;
    lVar3 = DAT_00005ad8;
    if ((DAT_00005ac8 != 0 && DAT_00005ad0 != 0) && DAT_00005ad8 != 0) {
LAB_00004a64:
      DAT_00005ad8 = lVar3;
      DAT_00005ad0 = lVar4;
      DAT_00005ac8 = lVar2;
      *param_4 = (long)FUN_00004a98;
      return 0;
    }
    lVar2 = (*(code *)*param_3)(s__usr_lib_system_libsystem_pthrea_00005eca,0x10);
    if (lVar2 != 0) {
      (*(code *)param_3[1])(lVar2,s_pthread_create_00005ef2);
      lVar2 = FUN_00005b6c();
      if ((lVar2 != 0) &&
         (lVar3 = (*(code *)*param_3)(s__usr_lib_system_libsystem_c_dyli_00005f01,0x10), lVar3 != 0)
         ) {
        (*(code *)param_3[1])(lVar3,s_malloc_00005f23);
        lVar4 = FUN_00005b6c();
        if (lVar4 != 0) {
          (*(code *)param_3[1])(lVar3,&DAT_00005f2a);
          lVar3 = FUN_00005b6c();
          if (lVar3 != 0) goto LAB_00004a64;
        }
      }
    }
    *param_4 = 0;
  }
  return 0x910006;
}



undefined8 FUN_00004a98(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  code *pcVar1;
  code *pcVar2;
  undefined8 *puVar3;
  undefined8 uVar4;
  
  pcVar2 = DAT_00005ad8;
  pcVar1 = DAT_00005ac8;
  if ((DAT_00005ac8 == Reset || DAT_00005ad0 == Reset) || DAT_00005ad8 == Reset) {
    uVar4 = 0x16;
  }
  else {
    puVar3 = (undefined8 *)(*DAT_00005ad0)(0x10);
    if (puVar3 == (undefined8 *)0x0) {
      uVar4 = 0xc;
    }
    else {
      *puVar3 = param_3;
      puVar3[1] = param_4;
      uVar4 = FUN_00005ba0(FUN_00004b64,0);
      uVar4 = (*pcVar1)(param_1,param_2,uVar4,puVar3);
      if ((int)uVar4 != 0) {
        FUN_000037b4(puVar3,0,0x10);
        (*pcVar2)(puVar3);
      }
    }
  }
  return uVar4;
}



undefined8 FUN_00004b64(long *param_1)

{
  code *pcVar1;
  code *pcVar2;
  undefined8 uVar3;
  
  pcVar1 = DAT_00005ad8;
  if ((param_1 == (long *)0x0) || (*param_1 == 0)) {
    uVar3 = 0;
  }
  else {
    UnkSytemRegWrite(3,4,0xf,2,7,0);
    InstructionSynchronizationBarrier();
    pcVar2 = (code *)FUN_00005b6c(*param_1);
    *param_1 = (long)pcVar2;
    uVar3 = (*pcVar2)(param_1[1]);
    FUN_000037b4(param_1,0,0x10);
    if (pcVar1 != Reset) {
      (*pcVar1)(param_1);
    }
  }
  return uVar3;
}



undefined8
FUN_00004be8(long param_1,long param_2,undefined8 param_3,long param_4,int param_5,uint param_6)

{
  ulong uVar1;
  short sVar2;
  undefined8 uVar3;
  ulong uVar4;
  ulong uVar5;
  undefined8 uVar6;
  ulong local_68;
  ulong local_60;
  long local_58;
  
  uVar3 = 0xad001;
  if ((param_1 != 0) && (param_4 != 0)) {
    local_68 = 0;
    uVar3 = FUN_0000468c(param_1,*(long *)(param_4 + 8) + (ulong)param_6 +
                                 (ulong)((uint)*(ushort *)(param_4 + 4) * param_5),&local_68);
    if ((int)uVar3 == 0) {
      uVar6 = 0x920006;
      sVar2 = *(short *)(param_4 + 6);
      if ((sVar2 == 6) || (sVar2 == 2)) {
        uVar3 = 0xad001;
        if ((local_68 != 0) &&
           ((uVar3 = uVar6, *(ulong *)(param_1 + 0x58) <= local_68 &&
            (uVar5 = local_68,
            local_68 < *(ulong *)(param_1 + 0x58) + (ulong)*(uint *)(param_1 + 0xa8))))) {
          do {
            local_58 = 0;
            FUN_00003628(&local_60,uVar5,8);
            if ((long)local_60 < 0) {
              if ((uint)param_3 <= ((uint)local_60 & 0xffffff)) {
                return 0x920001;
              }
              local_58 = *(long *)(param_2 + (local_60 & 0xffffff) * 8) + (local_60 >> 0x18 & 0xff);
            }
            else {
              uVar1 = local_60 & 0xfffffffff | (local_60 >> 0x24) << 0x38;
              if (sVar2 == 2) {
                local_58 = (uVar1 + *(long *)(param_1 + 0x60)) - *(long *)(param_1 + 0x50);
              }
              else {
                local_58 = uVar1 + *(long *)(param_1 + 0x60);
              }
            }
            FUN_00003628(uVar5,&local_58,8);
            if ((local_60 >> 0x33 & 0xfff) == 0) {
              return 0;
            }
            uVar5 = uVar5 + (((uint)(local_60 >> 0x33) & 0xfff) << 2);
            uVar4 = *(ulong *)(param_1 + 0x58);
            uVar1 = uVar4 + *(uint *)(param_1 + 0xa8);
          } while ((uVar5 >= uVar4 && uVar5 <= uVar1) && (uVar5 < uVar4 || uVar1 != uVar5));
        }
      }
      else if (sVar2 == 1) {
        uVar3 = FUN_00004da0(param_1,local_68,param_2,param_3);
      }
      else {
        uVar3 = 0x920005;
      }
    }
  }
  return uVar3;
}



undefined8 FUN_00004da0(long param_1,ulong *param_2,long param_3,uint param_4)

{
  ulong *puVar1;
  ulong uVar2;
  long lVar3;
  ulong uVar4;
  
  do {
    uVar4 = *param_2;
    lVar3 = *(long *)(param_1 + 0x60);
    puVar1 = param_2;
    if (lVar3 != *(long *)(param_1 + 0x58)) {
      puVar1 = (ulong *)((long)param_2 + (lVar3 - *(long *)(param_1 + 0x58)));
    }
    if ((long)uVar4 < 0) {
      if ((uVar4 >> 0x3e & 1) == 0) {
        lVar3 = lVar3 + (uVar4 & 0xffffffff);
      }
      else {
        if (param_4 <= ((uint)uVar4 & 0xffff)) {
          return 0x920001;
        }
        lVar3 = *(long *)(param_3 + (uVar4 & 0xffff) * 8);
        uVar2 = 0;
        if (lVar3 == 0) goto LAB_00004e78;
      }
      uVar2 = uVar4 >> 0x20 & 0xffff;
      if ((uVar4 & 0x1000000000000) != 0) {
        uVar2 = (ulong)puVar1 & 0xffffffffffff | (uVar4 >> 0x20) << 0x30;
      }
      uVar2 = FUN_00005be0(lVar3,uVar4 >> 0x31 & 3,uVar2);
    }
    else if ((uVar4 >> 0x3e & 1) == 0) {
      uVar2 = ((uVar4 & 0x7f80000000000) * 0x2000 + lVar3 +
              ((long)(uVar4 << 0x15) >> 0x15 & 0xffffffffffffffU)) - *(long *)(param_1 + 0x50);
    }
    else {
      if (param_4 <= ((uint)uVar4 & 0xffff)) {
        return 0x920001;
      }
      uVar2 = uVar4 >> 0x20 & 0x7ffff;
      if ((uVar4 & 0x40000) != 0) {
        uVar2 = uVar4 >> 0x20 | 0xfffffffffffc0000;
      }
      uVar2 = *(long *)(param_3 + (uVar4 & 0xffff) * 8) + uVar2;
    }
LAB_00004e78:
    *param_2 = uVar2;
    if ((uVar4 >> 0x33 & 0x7ff) == 0) {
      return 0;
    }
    param_2 = param_2 + ((uint)(uVar4 >> 0x33) & 0x7ff);
  } while( true );
}



long FUN_00004ea8(int param_1,long *param_2)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  
  iVar1 = *(int *)(*param_2 + 0x10);
  if (iVar1 != 0) {
    iVar2 = 0;
    piVar3 = (int *)(param_2[0xd] + 0x20);
    do {
      if (*piVar3 == 0x19) {
        if (iVar2 == param_1) {
          return (param_2[0xb] - param_2[10]) + *(long *)(piVar3 + 6);
        }
        iVar2 = iVar2 + 1;
      }
      piVar3 = (int *)((long)piVar3 + (ulong)(uint)piVar3[1]);
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  return 0;
}



undefined8
FUN_00004f04(long *param_1,long param_2,uint param_3,int param_4,long param_5,undefined8 param_6,
            undefined8 param_7,long param_8,undefined4 param_9)

{
  byte bVar1;
  int iVar2;
  undefined8 uVar3;
  long local_60;
  long local_58;
  
  local_58 = 0;
  if (param_2 == 0) {
    uVar3 = 0x91000c;
  }
  else {
    uVar3 = FUN_00004784(param_2,param_6,param_7,&local_58,param_9);
    if ((int)uVar3 == 0x910006 && (param_3 & 1) != 0) {
      param_5 = 0;
      local_58 = 0;
    }
    else if ((int)uVar3 != 0) {
      return uVar3;
    }
    iVar2 = FUN_0000505c(param_2,param_7,&local_60);
    if (iVar2 == 0) {
      param_5 = 0;
      local_58 = local_60;
    }
    bVar1 = *(byte *)(param_8 + 0xac);
    if ((bVar1 >> 6 & 1) != 0) {
      local_58 = FUN_00005b6c(local_58);
      bVar1 = *(byte *)(param_8 + 0xac);
    }
    if ((bVar1 >> 6 & 1) == 0) {
      if (param_1 < *(long **)(param_8 + 0x58)) {
        return 0x910007;
      }
      if ((long *)((long)*(long **)(param_8 + 0x58) + (ulong)*(uint *)(param_8 + 0xa8)) <= param_1)
      {
        return 0x910007;
      }
    }
    if (param_4 == 3) {
      local_58._0_4_ = (((int)param_5 + (int)local_58) - (int)param_1) + -4;
    }
    else {
      if (param_4 != 2) {
        if (param_4 == 1) {
          *param_1 = param_5 + local_58;
          return 0;
        }
        return 0;
      }
      local_58._0_4_ = (int)param_5 + (int)local_58;
    }
    uVar3 = 0;
    *(int *)param_1 = (int)local_58;
  }
  return uVar3;
}



undefined8 FUN_0000505c(undefined8 param_1,undefined8 *param_2,undefined8 *param_3)

{
  bool bVar1;
  long lVar2;
  int iVar3;
  long lVar4;
  long lVar5;
  long lVar6;
  long lVar7;
  long lVar8;
  long lVar9;
  long lVar10;
  long lVar11;
  ulong uVar12;
  ulong uVar13;
  undefined8 uVar14;
  int *piVar15;
  uint uVar16;
  ulong uVar17;
  ulong uVar18;
  code *pcVar19;
  undefined1 auStack_80 [8];
  long local_78;
  
  iVar3 = FUN_00003840(param_1,s__asl_vlog_00005f2f);
  if (iVar3 == 0) {
    pcVar19 = FUN_000053ac;
  }
  else {
    iVar3 = FUN_00003840(param_1,s__asl_log_00005f39);
    if (iVar3 != 0) {
      return 0x91000b;
    }
    pcVar19 = FUN_00005404;
  }
  if (((((DAT_00005ae0 == 0 || DAT_00005ae8 == 0) || DAT_00005af0 == 0) || DAT_00005af8 == 0) ||
      DAT_00005b00 == 0) || DAT_00005b08 == 0) {
    uVar14 = 0x91000b;
    lVar4 = (*(code *)*param_2)(s__usr_lib_system_libsystem_trace__00005f42,0x10);
    if (lVar4 != 0) {
      (*(code *)param_2[1])(lVar4,s__os_log_actual_00005f68);
      lVar5 = FUN_00005b6c();
      if (lVar5 != 0) {
        (*(code *)param_2[1])(lVar4,s__os_log_internal_00005f77);
        lVar5 = FUN_00005b6c();
        if (lVar5 != 0) {
          (*(code *)param_2[1])(lVar4,s__os_log_default_00005f88);
          lVar6 = FUN_00005b6c();
          if ((lVar6 != 0) &&
             (lVar7 = (*(code *)*param_2)(s__usr_lib_system_libsystem_c_dyli_00005f01,0x10),
             lVar7 != 0)) {
            (*(code *)param_2[1])(lVar7,s_vasprintf_00005f98);
            lVar8 = FUN_00005b6c();
            if (lVar8 != 0) {
              (*(code *)param_2[1])(lVar7,s__NSGetMachExecuteHeader_00005fa2);
              lVar9 = FUN_00005b6c();
              if (lVar9 != 0) {
                (*(code *)param_2[1])(lVar7,&DAT_00005f2a);
                lVar10 = FUN_00005b6c();
                if (((lVar10 != 0) && (iVar3 = (*(code *)param_2[2])(lVar5,auStack_80), iVar3 != 0))
                   && (*(int *)(local_78 + 0x10) != 0)) {
                  uVar16 = 0;
                  piVar15 = (int *)(local_78 + 0x20);
                  do {
                    if (((*piVar15 == 0x19) &&
                        (iVar3 = FUN_00003840(piVar15 + 2,s___TEXT_00005ddf), iVar3 == 0)) &&
                       (piVar15[0x10] != 0)) {
                      uVar18 = 0;
                      lVar11 = *(long *)(piVar15 + 6);
                      do {
                        iVar3 = FUN_00003840(piVar15 + uVar18 * 0x14 + 0x12,s___oslogstring_00005fba
                                            );
                        if (iVar3 == 0) {
                          uVar12 = *(ulong *)(piVar15 + uVar18 * 0x14 + 0x1c);
                          if (uVar12 != 0) {
                            uVar13 = 0;
                            uVar17 = 1;
                            do {
                              lVar2 = (local_78 - lVar11) +
                                      *(long *)(piVar15 + uVar18 * 0x14 + 0x1a) + uVar13;
                              iVar3 = FUN_000038b8(lVar2,s___public_s_00005fc8,uVar12 - uVar13);
                              if (iVar3 == 0) {
                                if (local_78 != 0) {
                                  uVar14 = 0;
                                  DAT_00005ae0 = lVar5;
                                  DAT_00005ae8 = lVar6;
                                  DAT_00005af0 = lVar8;
                                  DAT_00005af8 = lVar9;
                                  DAT_00005b00 = lVar10;
                                  DAT_00005b08 = lVar2;
                                  *param_3 = pcVar19;
                                }
                                goto LAB_00005370;
                              }
                              uVar12 = *(ulong *)(piVar15 + uVar18 * 0x14 + 0x1c);
                              bVar1 = uVar17 < uVar12;
                              uVar13 = uVar17;
                              uVar17 = (ulong)((int)uVar17 + 1);
                            } while (bVar1);
                          }
                        }
                        uVar18 = uVar18 + 1;
                      } while (uVar18 < (uint)piVar15[0x10]);
                    }
                    piVar15 = (int *)((long)piVar15 + (ulong)(uint)piVar15[1]);
                    uVar16 = uVar16 + 1;
                  } while (uVar16 < *(uint *)(local_78 + 0x10));
                }
              }
            }
LAB_00005370:
            (*(code *)param_2[3])(lVar7);
          }
        }
      }
      (*(code *)param_2[3])(lVar4);
    }
  }
  else {
    uVar14 = 0;
    *param_3 = pcVar19;
  }
  return uVar14;
}



undefined8
FUN_000053ac(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5)

{
  undefined8 uVar1;
  undefined8 local_28;
  
  local_28 = 0;
  if (DAT_00005af0 == Reset) {
    uVar1 = 0xffffffff;
  }
  else {
    (*DAT_00005af0)(&local_28,param_4,param_5);
    uVar1 = FUN_00005464(param_3,local_28);
  }
  return uVar1;
}



undefined8 FUN_00005404(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  undefined8 uVar1;
  undefined8 local_30;
  
  local_30 = 0;
  if (DAT_00005af0 == Reset) {
    uVar1 = 0xffffffff;
  }
  else {
    (*DAT_00005af0)(&local_30,param_4,&stack0x00000000);
    uVar1 = FUN_00005464(param_3,local_30);
  }
  return uVar1;
}



undefined8 FUN_00005464(uint param_1,long param_2)

{
  code *pcVar1;
  long lVar2;
  code *pcVar3;
  code *pcVar4;
  long lVar5;
  undefined8 uVar6;
  undefined1 local_58 [6];
  undefined2 local_52;
  
  lVar5 = DAT_00005b08;
  pcVar4 = DAT_00005b00;
  pcVar3 = DAT_00005af8;
  lVar2 = DAT_00005ae8;
  pcVar1 = DAT_00005ae0;
  if (((((DAT_00005ae0 != Reset && DAT_00005ae8 != 0) && DAT_00005af8 != Reset) &&
       DAT_00005b00 != Reset) && DAT_00005b08 != 0) && param_1 < 7 ||
      ((((DAT_00005ae0 != Reset && DAT_00005ae8 != 0) && DAT_00005af8 != Reset) &&
       DAT_00005b00 != Reset) && DAT_00005b08 != 0) && param_1 == 7) {
    FUN_000037b4(local_58,0,8);
    local_58[0] = 0;
    local_52 = 0x201;
    if (param_2 != 0) {
      uVar6 = (*pcVar3)();
      (*pcVar1)(uVar6,lVar2,local_58[param_1],lVar5);
      (*pcVar4)(param_2);
      return 0;
    }
  }
  return 0xffffffff;
}



long FUN_00005524(long *param_1)

{
  int iVar1;
  int *piVar2;
  
  iVar1 = *(int *)(*param_1 + 0x10);
  if (iVar1 != 0) {
    piVar2 = (int *)(param_1[0xd] + 0x20);
    do {
      if ((*piVar2 == 0x19) && ((*(byte *)(piVar2 + 0xf) >> 1 & 1) != 0)) {
        return *(long *)(piVar2 + 6) + (param_1[0xb] - param_1[10]);
      }
      piVar2 = (int *)((long)piVar2 + (ulong)(uint)piVar2[1]);
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  return 0;
}



undefined8
FUN_00005578(long param_1,uint *param_2,ulong *param_3,undefined8 param_4,undefined8 param_5)

{
  ulong uVar1;
  int iVar2;
  ulong local_38;
  
  local_38 = 0;
  if (((~(byte)param_2[1] & 0xe) == 0) &&
     ((((byte)param_2[1] >> 4 & 1) != 0 || ((*(ushort *)((long)param_2 + 6) >> 7 & 1) != 0)))) {
    local_38 = *(long *)(param_2 + 2) + *(long *)(param_1 + 0x60);
    *param_3 = local_38;
    if ((*(ushort *)((long)param_2 + 6) >> 3 & 1) == 0) {
      return 1;
    }
    local_38 = local_38 | 1;
  }
  else {
    if ((*(long *)(param_1 + 0x48) == 0) ||
       (uVar1 = *(long *)(param_1 + 0x48) + (ulong)*param_2,
       uVar1 < *(ulong *)(param_1 + 0x58) ||
       *(ulong *)(param_1 + 0x58) + (ulong)*(uint *)(param_1 + 0xa8) <= uVar1)) {
      return 0;
    }
    iVar2 = FUN_00004784(uVar1,param_4,param_5,&local_38,0);
    if (iVar2 != 0) {
      return 0;
    }
    *param_3 = local_38;
    iVar2 = FUN_0000505c(uVar1,param_5,&local_38);
    if (iVar2 != 0) {
      return 1;
    }
  }
  *param_3 = local_38;
  return 1;
}



undefined8 FUN_0000566c(undefined8 *param_1,long param_2,long param_3,long *param_4)

{
  long lVar1;
  long lVar2;
  undefined8 uVar3;
  
  uVar3 = 0xad001;
  if ((((param_1 != (undefined8 *)0x0) && (param_2 != 0)) && (param_3 != 0)) &&
     (param_4 != (long *)0x0)) {
    lVar1 = (*(code *)*param_1)(param_2,1);
    if (lVar1 == 0) {
      uVar3 = 0x1200b;
    }
    else {
      (*(code *)param_1[1])(lVar1,param_3);
      lVar2 = FUN_00005b6c();
      if (lVar2 == 0) {
        uVar3 = 0x12001;
      }
      else {
        uVar3 = 0;
        *param_4 = lVar2;
      }
      (*(code *)param_1[3])(lVar1);
    }
  }
  return uVar3;
}



void FUN_00005714(undefined8 param_1,undefined8 param_2,long param_3)

{
  undefined8 uVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  undefined *puVar5;
  long lVar6;
  
  lVar2 = *(long *)(param_3 + 0x30);
  puVar5 = *(undefined **)(lVar2 + 0x20);
  if (puVar5 != (undefined *)0x1339) {
    if (puVar5 == &LAB_00001338) {
      if (*(long *)(lVar2 + 0x28) == 0) {
        return;
      }
      FUN_00003628(lVar2,*(long *)(lVar2 + 0x28),0x330);
      lVar3 = FUN_00005b6c(*(undefined8 *)(lVar2 + 0x110));
      lVar3 = lVar3 + 4;
      goto LAB_00005800;
    }
    if (puVar5 != &DAT_00001337) {
      return;
    }
  }
  lVar4 = *(long *)(lVar2 + 0x28);
  if (lVar4 == 0) {
    return;
  }
  FUN_00003628(lVar4,lVar2,0x330);
  lVar3 = *(long *)(lVar4 + 0x330);
  *(undefined1 **)(lVar2 + 0x20) = &LAB_00001338;
  uVar1 = FUN_00005be0(lVar4 + 0x3fe0,2,0xcbed);
  *(undefined8 *)(lVar2 + 0x108) = uVar1;
  *(int *)(lVar4 + 0x3ffc) = (int)*(undefined8 *)(lVar2 + 0x10);
  *(int *)(lVar4 + 0x3fec) = (int)*(undefined8 *)(lVar2 + 0x10);
  if (puVar5 == (undefined *)0x1339) {
    lVar6 = *(long *)(lVar4 + 0x338);
    uVar1 = FUN_00005be0(0x1000,1,lVar4 + 0x4030);
    *(undefined8 *)(lVar4 + 0x4028) = uVar1;
    lVar6 = *(long *)(lVar2 + 0x18) + lVar6;
  }
  else {
    lVar6 = *(long *)(lVar2 + 0x18);
  }
  *(long *)(lVar2 + 0xa8) = lVar6;
LAB_00005800:
  uVar1 = FUN_00005ba0(lVar3,0x7481);
  *(undefined8 *)(lVar2 + 0x110) = uVar1;
  return;
}



undefined8
FUN_0000581c(undefined8 param_1,undefined8 param_2,long param_3,long *param_4,undefined8 *param_5)

{
  int iVar1;
  undefined8 uVar2;
  ulong uVar3;
  int *piVar4;
  int *piVar5;
  int *piVar6;
  int *piVar7;
  int *piVar8;
  uint uVar9;
  
  uVar2 = 0x18006;
  if (*(int *)(param_3 + 0x10) != 0) {
    piVar5 = (int *)0x0;
    uVar9 = 0;
    piVar4 = (int *)(param_3 + 0x20);
    piVar7 = (int *)0x0;
    do {
      piVar8 = piVar7;
      if ((piVar7 != (int *)0x0) && (piVar5 != (int *)0x0)) break;
      if (*piVar4 == 0x19) {
        iVar1 = FUN_00003840(piVar4 + 2,s___TEXT_00005ddf);
        piVar8 = piVar4;
        if (iVar1 != 0) {
          piVar8 = piVar7;
        }
        if (piVar5 == (int *)0x0) {
          iVar1 = FUN_00003840(piVar4 + 2,param_1);
          if ((iVar1 == 0) && (piVar4[0x10] != 0)) {
            uVar3 = 0;
            piVar7 = piVar4 + 0x12;
            piVar6 = (int *)0x0;
            do {
              iVar1 = FUN_00003840(piVar7,param_2);
              piVar5 = piVar7;
              if (iVar1 != 0) {
                piVar5 = piVar6;
              }
              uVar3 = uVar3 + 1;
              piVar7 = piVar7 + 0x14;
              piVar6 = piVar5;
            } while (uVar3 < (uint)piVar4[0x10]);
          }
          else {
            piVar5 = (int *)0x0;
          }
        }
      }
      piVar4 = (int *)((long)piVar4 + (ulong)(uint)piVar4[1]);
      uVar9 = uVar9 + 1;
      piVar7 = piVar8;
    } while (uVar9 < *(uint *)(param_3 + 0x10));
    uVar2 = 0x18006;
    if ((piVar8 != (int *)0x0) && (piVar5 != (int *)0x0)) {
      uVar2 = 0;
      *param_4 = (param_3 - *(long *)(piVar8 + 6)) + *(long *)(piVar5 + 8);
      *param_5 = *(undefined8 *)(piVar5 + 10);
    }
  }
  return uVar2;
}



/* WARNING: Type propagation algorithm not settling */

undefined8
FUN_0000596c(long param_1,undefined8 param_2,uint param_3,ulong param_4,long param_5,ulong *param_6)

{
  ulong uVar1;
  ulong uVar2;
  int iVar3;
  long lVar4;
  long lVar5;
  ulong *puVar6;
  ulong uVar7;
  ulong uVar8;
  undefined8 uStack_a8;
  ulong auStack_a0 [2];
  ulong *local_90;
  long local_88;
  undefined1 auStack_80 [16];
  long local_70;
  ulong local_68;
  
  puVar6 = (ulong *)((long)auStack_a0 - ((ulong)(param_3 + 1) * 8 + 0xf & 0xffffffff0));
  FUN_000037b4(puVar6,0);
  uVar7 = (param_4 + param_5) - 1;
  if (param_4 <= uVar7) {
    uVar8 = 0;
    auStack_a0[1] = (ulong)param_3;
    lVar5 = auStack_a0[1] << 3;
    local_90 = param_6;
    local_88 = (long)auStack_a0;
    do {
      iVar3 = (**(code **)(param_1 + 0x10))(uVar7,auStack_80);
      uVar2 = local_68;
      if ((iVar3 != 0) && (local_68 != uVar8)) {
        lVar4 = lVar5;
        if (param_3 != 0) {
          do {
            *(undefined8 *)((long)puVar6 + lVar4) = ((undefined8 *)((long)puVar6 + lVar4))[-1];
            lVar4 = lVar4 + -8;
          } while (lVar4 != 0);
        }
        *puVar6 = uVar2;
        if ((local_70 != 0) && (iVar3 = FUN_00003840(local_70,param_2), iVar3 == 0)) {
          *local_90 = puVar6[auStack_a0[1]];
          return 0;
        }
        uVar8 = uVar7;
        if (uVar2 < param_4 + param_5 && param_4 <= uVar2) {
          uVar8 = uVar2;
        }
        uVar1 = uVar7;
        if (uVar2 < uVar7) {
          uVar1 = uVar8;
        }
        uVar8 = 0;
        if (uVar2 != 0) {
          uVar7 = uVar1;
          uVar8 = uVar2;
        }
      }
      uVar7 = uVar7 - 1;
    } while (param_4 <= uVar7);
  }
  return 0x18005;
}



bool FUN_00005b50(void)

{
  int iVar1;
  
  iVar1 = FUN_00005cbc();
  return iVar1 != 0;
}



undefined8 FUN_00005b6c(undefined8 param_1)

{
  return param_1;
}



undefined8 FUN_00005b84(void)

{
  return 0;
}



undefined8 FUN_00005ba0(undefined8 param_1,undefined8 param_2)

{
  int iVar1;
  undefined8 uVar2;
  
  iVar1 = FUN_00005cbc();
  if (iVar1 != 0) {
    uVar2 = FUN_00005c9c(param_1,param_2);
    return uVar2;
  }
  return param_1;
}



undefined8 FUN_00005be0(undefined8 param_1,undefined4 param_2,undefined8 param_3)

{
  int iVar1;
  undefined8 uVar2;
  
  iVar1 = FUN_00005cbc();
  if (iVar1 != 0) {
    switch(param_2) {
    case 0:
      uVar2 = FUN_00005c9c(param_1,param_3);
      return uVar2;
    case 1:
      uVar2 = FUN_00005cac(param_1,param_3);
      return uVar2;
    case 2:
      uVar2 = FUN_00005ca4(param_1,param_3);
      return uVar2;
    case 3:
      uVar2 = FUN_00005cb4(param_1,param_3);
      return uVar2;
    }
  }
  return param_1;
}



void FUN_00005c9c(void)

{
  return;
}



void FUN_00005ca4(void)

{
  return;
}



void FUN_00005cac(void)

{
  return;
}



void FUN_00005cb4(void)

{
  return;
}



/* WARNING: Removing unreachable block (ram,0x00005ce4) */

undefined8 FUN_00005cbc(void)

{
  return 0;
}



void FUN_00005ce8(code *UNRECOVERED_JUMPTABLE)

{
                    /* WARNING: Could not recover jumptable at 0x00005d08. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)();
  return;
}



void FUN_00005d0c(code *UNRECOVERED_JUMPTABLE,undefined4 param_2,undefined8 param_3,long param_4)

{
  undefined4 auStack_40 [8];
  
  *(undefined4 *)((long)auStack_40 + param_4) = param_2;
                    /* WARNING: Could not recover jumptable at 0x00005d28. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)();
  return;
}



void FUN_00005d2c(code *UNRECOVERED_JUMPTABLE,undefined4 param_2,undefined8 param_3,long param_4)

{
  undefined4 auStack_40 [12];
  
  *(undefined4 *)((long)auStack_40 + param_4) = param_2;
                    /* WARNING: Could not recover jumptable at 0x00005d48. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)();
  return;
}



void FUN_00005d4c(code *UNRECOVERED_JUMPTABLE,undefined4 param_2,undefined8 param_3,long param_4)

{
  undefined4 auStack_50 [4];
  
  *(undefined4 *)((long)auStack_50 + param_4) = param_2;
                    /* WARNING: Could not recover jumptable at 0x00005d70. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)();
  return;
}



void FUN_00005d74(code *UNRECOVERED_JUMPTABLE,undefined4 param_2,undefined8 param_3,long param_4)

{
  undefined4 auStack_50 [8];
  
  *(undefined4 *)((long)auStack_50 + param_4) = param_2;
                    /* WARNING: Could not recover jumptable at 0x00005d94. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)();
  return;
}


