RM=rm -rf
RMFORCE=rm -rf
SRCS= genGoStructRst.go
all: exe

exe: $(SRCS)
	go build $(SRCS)
	mkdir -p rstFiles

clean:
	$(RM) genGoStructRst rstFiles
