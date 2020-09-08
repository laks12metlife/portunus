import { observer } from 'mobx-react';

import Typography from '@wui/basics/typography';

import { register } from 'utils/API';
import KeepParamsLink from 'components/KeepParamsLink';
import AuthBase from './AuthBase';

const Register = () => (
  <AuthBase
    submitCredentials={register}
    submitText="Register"
    headerText="Create Account"
    confirmPassword
    showTerms
    showCaptcha
  >
    <Typography>
      Already have an account?&nbsp;
      <KeepParamsLink href="/login">Login</KeepParamsLink>
    </Typography>
  </AuthBase>
);

export default observer(Register);
