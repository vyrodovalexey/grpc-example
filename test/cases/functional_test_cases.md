# Functional Test Cases

## Overview
This document describes the functional test cases for the gRPC Test Server.

## Test Categories

### 1. Unary RPC Tests (`unary_test.go`)

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| TestFunctional_Unary_SimpleMessage | Send a simple "Hello, gRPC!" message | Message echoed back with timestamp |
| TestFunctional_Unary_EmptyMessage | Send an empty string message | Empty string echoed back with timestamp |
| TestFunctional_Unary_LargeMessage | Send a 1KB message (1024 'A' characters) | Full message echoed back |
| TestFunctional_Unary_UnicodeMessage | Send Unicode characters | Unicode message echoed back correctly |
| TestFunctional_Unary_ConcurrentRequests | Send 10 parallel requests | All requests succeed with correct responses |
| TestFunctional_Unary_RequestWithDeadline | Send request with 5s deadline | Request completes successfully |
| TestFunctional_Unary_RequestWithExpiredDeadline | Send request with expired deadline | DeadlineExceeded error |
| TestFunctional_Unary_TableDriven | Multiple message types (ASCII, numbers, special chars, JSON) | All messages echoed correctly |

### 2. Server Streaming Tests (`server_stream_test.go`)

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| TestFunctional_ServerStream_FiveValues | Request 5 values with 10ms interval | Receive exactly 5 responses |
| TestFunctional_ServerStream_ZeroValues | Request 0 values | InvalidArgument error |
| TestFunctional_ServerStream_HundredValues | Request 100 values | Receive exactly 100 responses |
| TestFunctional_ServerStream_CancelAfterThree | Cancel stream after receiving 3 values | Receive 3 values, then error on next recv |
| TestFunctional_ServerStream_SequentialSequenceNumbers | Verify sequence numbers | Sequences are 1, 2, 3, 4, 5 |
| TestFunctional_ServerStream_IncreasingTimestamps | Verify timestamps | Each timestamp > previous |
| TestFunctional_ServerStream_CustomInterval | Request with 100ms interval | Takes at least 300ms for 3 values |
| TestFunctional_ServerStream_RandomValues | Request 10 values | Values are not all identical |
| TestFunctional_ServerStream_TableDriven | Various count/interval combinations | Correct behavior for each case |

### 3. Bidirectional Streaming Tests (`bidi_stream_test.go`)

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| TestFunctional_BidiStream_FiveValuesTransformed | Send 5 values with double operation | Receive 5 transformed responses |
| TestFunctional_BidiStream_DoubleOperation | Test double operation with various values | value * 2 for each |
| TestFunctional_BidiStream_SquareOperation | Test square operation with various values | value * value for each |
| TestFunctional_BidiStream_NegateOperation | Test negate operation with various values | -value for each |
| TestFunctional_BidiStream_MixedOperations | Mix of double, square, negate | Correct transformation for each |
| TestFunctional_BidiStream_ZeroValues | Close stream without sending | Receive EOF immediately |
| TestFunctional_BidiStream_RapidSendWithoutWaiting | Send 50 values rapidly | All 50 responses received correctly |
| TestFunctional_BidiStream_CloseSendAndReceiveRemaining | Close send, then receive | All pending responses received |
| TestFunctional_BidiStream_CancelMidStream | Cancel context mid-stream | Canceled error on subsequent operations |
| TestFunctional_BidiStream_InvalidOperation | Send invalid operation | InvalidArgument error |
| TestFunctional_BidiStream_TableDriven | Various operation/value combinations | Correct results for each case |

### 4. Error Scenario Tests (`error_test.go`)

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| TestFunctional_Error_ConnectToWrongPort | Connect to non-listening port | Unavailable error |
| TestFunctional_Error_RequestTimeout | Request with 1ns timeout | DeadlineExceeded error |
| TestFunctional_Error_ServerShutdownMidRequest | Stop server during streaming | Unavailable/Canceled/Internal error |
| TestFunctional_Error_StreamCancellation | Cancel stream context | Canceled error |
| TestFunctional_Error_InvalidStreamParameters | Invalid count/interval values | InvalidArgument error |
| TestFunctional_Error_BidiStreamInvalidOperation | Unknown operation in bidi stream | InvalidArgument error |
| TestFunctional_Error_ContextCancelledBeforeRequest | Pre-cancelled context | Canceled error |
| TestFunctional_Error_MultipleErrors | Multiple error scenarios in sequence | Each error handled correctly |

## Test Execution

### Run All Functional Tests
```bash
go test -v -race -tags=functional ./test/functional/...
```

### Run Specific Test File
```bash
go test -v -race -tags=functional ./test/functional/... -run TestFunctional_Unary
```

### Run With Coverage
```bash
go test -v -race -tags=functional -coverprofile=coverage.out ./test/functional/...
go tool cover -html=coverage.out
```

## Test Infrastructure

### Suite Setup (`suite_test.go`)
- Starts a real gRPC server on a random available port
- Creates a gRPC client connection
- Provides helper functions for test context creation
- Cleans up resources after all tests complete

### Test Service (`test_service.go`)
- Implements the TestServiceServer interface
- Mirrors the production service implementation
- Used by the test suite for functional testing
