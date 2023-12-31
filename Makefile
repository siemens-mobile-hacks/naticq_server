APP=ig11
SRCS=statgen.cpp md5.cpp snaccache.cpp main_freebsd.cpp flap.cpp icqkid2.cpp
OBJS=${SRCS:.cpp=.o}

CC=clang++
CXXFLAGS=-O2 -DNDEBUG
LDFLAGS= -pthread

link: writerevision ${OBJS}
	@${CC} -o ${APP} ${CXXFLAGS} ${OBJS} ${LDFLAGS}
	@strip ${APP}
clean:
	@rm -rf *.o ${APP}

writerevision:
	@echo "#define __SVN_REVISION__ \"`svnversion`\"" > revision.h
