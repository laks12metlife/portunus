import getEnv from 'zg_utils/getEnv';

const keys = ['sentryDsn', 'sentryEnvironment', 'captchaSiteKey'];

export default getEnv(keys);
