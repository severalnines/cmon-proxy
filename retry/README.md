# retry
--
    import "."


## Usage

#### func  Do

```go
func Do(cmd Command, cleaner Cleaner, count int, wait time.Duration) error
```
Do will retry cmd for count times. cleaner will be executed if cmd returned an
error.

#### type Cleaner

```go
type Cleaner func(error, int) error
```

Cleaner func is executed between if a Command failed with error.

#### type Command

```go
type Command func(int) error
```

Command func to execute.
