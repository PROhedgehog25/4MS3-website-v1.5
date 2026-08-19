self.addEventListener(
    "push",
    event => {

        if (
            !event.data
        ) {

            return;

        }


        let data;


        try {

            data =
                event.data.json();

        }

        catch {

            data = {

                title:
                    "4MS3 Shoutbox",

                body:
                    event.data.text(),

                url:
                    "/#shoutbox"

            };

        }


        const title =
            data.title ||
            "4MS3 Shoutbox";


        const options = {

            body:
                data.body ||
                "New Shoutbox message.",

            icon:
                "/star.png",

            badge:
                "/star.png",

            data: {

                url:
                    data.url ||
                    "/#shoutbox"

            }

        };


        event.waitUntil(

            self.registration
                .showNotification(
                    title,
                    options
                )

        );

    }
);


self.addEventListener(
    "notificationclick",
    event => {

        event.notification.close();


        const url =
            event.notification.data &&
            event.notification.data.url
                ? event.notification.data.url
                : "/#shoutbox";


        event.waitUntil(

            clients.matchAll({
                type:
                    "window",
                includeUncontrolled:
                    true
            })
            .then(
                clientList => {

                    for (
                        const client
                        of clientList
                    ) {

                        if (
                            "focus" in client
                        ) {

                            client.navigate(
                                url
                            );

                            return client.focus();

                        }

                    }


                    if (
                        clients.openWindow
                    ) {

                        return clients.openWindow(
                            url
                        );

                    }

                }
            )

        );

    }
);