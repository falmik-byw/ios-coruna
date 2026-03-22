



void _CFRelease(void)

{
                    /* WARNING: Could not recover jumptable at 0x00007de8. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)((int)&DAT_00007dec + DAT_00007dec))();
  return;
}



void _IOObjectRelease(void)

{
                    /* WARNING: Could not recover jumptable at 0x00007df8. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)((int)&DAT_00007dfc + DAT_00007dfc))();
  return;
}



void _IORegistryEntryCreateCFProperty(void)

{
                    /* WARNING: Could not recover jumptable at 0x00007e08. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)((int)&DAT_00007e0c + DAT_00007e0c))();
  return;
}



void _IOServiceGetMatchingService(void)

{
                    /* WARNING: Could not recover jumptable at 0x00007e18. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)((int)&DAT_00007e1c + DAT_00007e1c))();
  return;
}



void _IOServiceMatching(void)

{
                    /* WARNING: Could not recover jumptable at 0x00007e28. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)((int)&DAT_00007e2c + DAT_00007e2c))();
  return;
}



void _objc_autoreleasePoolPop(void)

{
                    /* WARNING: Could not recover jumptable at 0x00007e38. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)((int)&DAT_00007e3c + DAT_00007e3c))();
  return;
}



void _objc_autoreleasePoolPush(void)

{
                    /* WARNING: Could not recover jumptable at 0x00007e48. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)((int)&DAT_00007e4c + DAT_00007e4c))();
  return;
}



/* WARNING: Control flow encountered bad instruction data */

void _objc_msgSend(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* WARNING: Control flow encountered bad instruction data */

void dyld_stub_binder(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


