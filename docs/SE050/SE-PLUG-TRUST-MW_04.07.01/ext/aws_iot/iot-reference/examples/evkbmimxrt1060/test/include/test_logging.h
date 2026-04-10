#ifndef TEST_LOGGING_H
#define TEST_LOGGING_H

void TEST_CacheResult( char cResult );

void TEST_SubmitResultBuffer( void );

void TEST_NotifyTestStart( void );

void TEST_NotifyTestFinished( void );

void TEST_SubmitResult( const char * pcResult );

#endif /* TEST_LOGGING_H */
