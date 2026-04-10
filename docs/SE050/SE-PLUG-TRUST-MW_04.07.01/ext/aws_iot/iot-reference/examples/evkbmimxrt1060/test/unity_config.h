#ifndef UNITY_CONFIG_H
#define UNITY_CONFIG_H

#ifndef UNITY_OUTPUT_CHAR

#define UNITY_OUTPUT_CHAR( a )     TEST_CacheResult( a )
#endif
#ifndef UNITY_OUTPUT_FLUSH
#define UNITY_OUTPUT_FLUSH()       TEST_SubmitResultBuffer()
#endif
#ifndef UNITY_OUTPUT_START
#define UNITY_OUTPUT_START()       TEST_NotifyTestStart()
#endif
#ifndef UNITY_OUTPUT_COMPLETE
#define UNITY_OUTPUT_COMPLETE()    TEST_NotifyTestFinished()

#endif /* UNITY_CONFIG_H */
