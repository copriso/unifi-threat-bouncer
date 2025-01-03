import {alarm, PrismaClient} from '@prisma/client'
import {WatcherClient} from "crowdsec-client";
import {AddAlertsRequest, Alert} from "crowdsec-client/lib/types/types/generated/data-contracts";
import * as fs from "node:fs/promises";


const prisma = new PrismaClient();

const watcherClient = new WatcherClient({
    url: process.env.CROWDSEC_URL!,
    auth: {
        machineID: process.env.CROWDSEC_MACHINE_ID!,
        password: process.env.CROWDSEC_PASSWORD!,
        autoRenew: true,
    }
});


const LASTRUN_FILE = '../lastrun';

function convert2Alert(alarms: alarm[]): AddAlertsRequest {
    const alerts: AddAlertsRequest = [];
    alarms.forEach(alarm => {
        const a: Alert = {
            machine_id: process.env.CROWDSEC_MACHINE_ID!,
            scenario: 'unifi/' + alarm.inner_alert_category,
            scenario_hash: alarm.unique_alertid,
            scenario_version: '1.0',
            start_at: alarm.datetime.toISOString(),
            stop_at: '168h',
            events_count: 1,
            events: [],
            message: alarm.inner_alert_signature,
            capacity: 0,
            leakspeed: '',
            simulated: false,
            source: {
                value: alarm.src_ip,
                scope: 'ip',
                latitude: alarm.srcipGeo.latitude,
                longitude: alarm.srcipGeo.longitude,
                as_name: alarm.srcipASN.trim(),
                cn: alarm.srcipCountry
            },
            decisions: [{
                origin: 'cscli',
                type: 'ban',
                scope: 'ip',
                value: alarm.src_ip,
                duration: '168h',
                scenario: 'unifi/' + alarm.inner_alert_category,
            }]
        }

        alerts.push(a);
    })

    return alerts;
}

async function getLastRun() {
    return await (async () => {
        try {
            const lastrun = await fs.readFile(LASTRUN_FILE, {encoding: 'utf8'});
            return parseInt(lastrun);
        } catch (error) {
            return 0;
        }
    })();
}

async function storeLastRun(timestamp: Date) {
    console.log(`Storing lastrun ${timestamp.toISOString()}`);
    await fs.writeFile(LASTRUN_FILE, (timestamp.getTime()) + "", {flag: 'w+'});
}

// get last run or 24h ago
async function getLastRunTimestamp() {
    let lastrunTS: number = await getLastRun();

    if (lastrunTS === 0 && process.env.INITIAL_TIMESTAMP !== undefined) {
        lastrunTS = parseInt(process.env.INITIAL_TIMESTAMP) ||
            (getUnixTimestamp() - 24 * 60 * 60 * 1000);
    }

    return lastrunTS;
}

function getUnixTimestamp() {
    return Math.floor(Date.now());
}


async function main() {
    const lastRun: number = await getLastRunTimestamp();

    // console.log('Importing Alerts since: ', new Date(lastRun).toISOString(), lastRun);


    const alarms = await prisma.alarm.findMany({
        where: {
            archived: false,
            timestamp: {gt: Math.floor(lastRun / 1000)}
        },
        take: 25,
        orderBy: [{
            time: 'desc'
        }]
    });


    const alerts = convert2Alert(alarms);

    if (alerts.length >= 1) {
        console.log(`New threats found: ${alarms.length}`);
        const x = await watcherClient.Alerts.pushAlerts(alerts)
        console.log(`Added ${x.length} alerts to crowdsec`);

        const latestAlert = alerts.shift();
        await storeLastRun(new Date(latestAlert?.start_at!));
    }

    setTimeout(main, 5000);
}

(async () => {
    console.log('Starting bouncer');
    await watcherClient.login();
    await main();
})();
