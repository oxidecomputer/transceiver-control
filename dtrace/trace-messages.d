#!/usr/sbin/dtrace -Zqs

xcvr_ctl$target:::message-sent
{
    peer = json(copyinstr(arg0), "ok");
    header = json(copyinstr(arg1), "ok");
    msg = json(copyinstr(arg2), "ok");
    printf("Sent message to %s\n", peer);
    printf("  header: %s\n", header);
    printf("  msg: %s\n", msg);
}

xcvr_ctl$target:::message-received
{
    peer = json(copyinstr(arg0), "ok");
    header = json(copyinstr(arg1), "ok");
    msg = json(copyinstr(arg2), "ok");
    body = json(msg, "body");
    printf("Recv message from %s\n", peer);
    printf("  header: %s\n", header);
    printf("  msg: %s\n", msg);
}
