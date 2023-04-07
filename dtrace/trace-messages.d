#!/usr/sbin/dtrace -Zqs

xcvr-ctl$target:::message-sent
{
	peer = json(copyinstr(arg0), "ok");
	msg = json(copyinstr(arg1), "ok");
    vers = json(msg, "version");
    body = json(msg, "body");
    printf("Sent message to %s\n", peer);
    printf("  version: %s\n", vers);
    printf("  body: %s\n", body);
}

xcvr-ctl$target:::message-received
{
	peer = json(copyinstr(arg0), "ok");
	msg = json(copyinstr(arg1), "ok");
    vers = json(msg, "version");
    body = json(msg, "body");
    printf("Recv message from %s\n", peer);
    printf("  version: %s\n", vers);
    printf("  body: %s\n", body);
}
