import { useEffect, useRef, useState } from 'react';
import { observer } from 'mobx-react';
import PropTypes from 'prop-types';
import { useRouter } from 'next/router';
import ReCaptcha from 'react-google-recaptcha';

import PasswordStrengthBar from 'react-password-strength-bar';

import Button from '@wui/input/button';
import Form from '@wui/layout/form';
import Spacer from '@wui/layout/spacer';
import Textbox from '@wui/input/textbox';
import Typography from '@wui/basics/typography';
import Tooltip from '@wui/layout/tooltip';
import Grid from '@wui/layout/grid';

import TermsCheckbox from 'components/TermsCheckbox';
import { useGlobalContext, useInputFieldState } from 'hooks';
import { MIN_PASSWORD_LENGTH } from 'utils/constants';

import env from 'utils/env';

const AuthBase = ({
  submitCredentials,
  submitText,
  headerText,
  showTerms,
  allowAutoComplete,
  showCaptcha,
  children,
}) => {
  const [email, onChangeEmail] = useInputFieldState('');
  const [password, onChangePassword] = useInputFieldState('');
  const [termsOfService, setTermsOfService] = useState(false);
  const [captchaSiteKey, setCaptchaSiteKey] = useState('');
  const [captchaKey, setCaptchaKey] = useState('');
  const recaptchaRef = useRef();
  const [inputErrors, setInputErrors] = useState({});
  const [processing, setProcessing] = useState(false);
  const router = useRouter();
  const {
    query: { next, localNext },
  } = router;
  const store = useGlobalContext();

  useEffect(() => {
    if (store.authenticated) {
      router.push('/');
    }
  }, []);

  useEffect(() => {
    if (showCaptcha) {
      env.captchaSiteKey.then(setCaptchaSiteKey);
    }
  }, []);

  const validateForm = () => {
    const errors = {};

    if (!email) {
      errors.email = 'Please enter your email';
    }

    if (!password) {
      errors.password = 'Please enter your password.';
    }

    if (password.length < MIN_PASSWORD_LENGTH) {
      errors.password = 'Password must be at least 8 characters.';
    }

    if (showTerms && !termsOfService) {
      errors.terms = 'Please agree to continue.';
    }

    if (showCaptcha && !captchaKey) {
      errors.non_field_errors = 'Please complete the captcha to continue.';
    }

    setInputErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleSuccess = response => {
    // Always prefer using the next parameter when it is present
    if (!next && localNext) {
      store.login();
      router.push(localNext);
    } else {
      window.location.href = response.data.next;
    }
  };

  const handleError = error => {
    if (error.response && error.response.data) {
      if (showCaptcha) {
        recaptchaRef.current.reset();
        setCaptchaKey('');
      }
      setInputErrors(error.response.data);
    } else {
      setInputErrors({ non_field_errors: 'An unknown error has occurred. Please try again.' });
    }
    setProcessing(false);
  };

  const handleSubmit = e => {
    e.preventDefault();
    if (processing || !validateForm()) {
      return;
    }

    setProcessing(true);

    submitCredentials({
      email: email.toLowerCase(),
      password,
      next,
      captchaKey,
    })
      .then(handleSuccess)
      .catch(handleError);
  };

  return (
    <>
      <Typography variant="h4">{headerText}</Typography>
      <Form error={inputErrors.non_field_errors} onSubmit={handleSubmit} noMargin>
        <Textbox
          name="email"
          type="email"
          label="Email"
          autoComplete={allowAutoComplete ? 'username' : 'off'}
          value={email}
          onChange={onChangeEmail}
          error={inputErrors.email}
        />
        {showTerms ? (
          <>
            <Textbox
              name="password"
              type="password"
              label="Password"
              autoComplete="off"
              value={password}
              onChange={onChangePassword}
              error={inputErrors.password}
            />
            <Grid container direction="row" alignItems="center" justify="space-between">
              <Grid item xs={11}>
                <PasswordStrengthBar password={password} minLength={MIN_PASSWORD_LENGTH} />
              </Grid>
              <Grid item xs={0.5}>
                <Tooltip title="Use 8+ characters with both letters and numbers" />
              </Grid>
            </Grid>
            <TermsCheckbox
              onChange={() => setTermsOfService(!termsOfService)}
              error={inputErrors.terms}
            />
          </>
        ) : (
          <Textbox
            name="password"
            type="password"
            label="Password"
            autoComplete="current-password"
            value={password}
            onChange={onChangePassword}
            error={inputErrors.password}
          />
        )}
        {showCaptcha &&
          (captchaSiteKey ? (
            <ReCaptcha
              sitekey={captchaSiteKey}
              onChange={value => setCaptchaKey(value)}
              ref={recaptchaRef}
            />
          ) : (
            <div>Loading...</div>
          ))}
        <Spacer v={24} />
        <Button
          variant="contained"
          color="primary"
          type="submit"
          noMinWidth
          size="large"
          disabled={processing}
        >
          {submitText}
        </Button>
      </Form>

      <Spacer v={16} />

      {children}

      <Spacer v={24} />
    </>
  );
};

AuthBase.propTypes = {
  submitCredentials: PropTypes.func.isRequired,
  submitText: PropTypes.string.isRequired,
  headerText: PropTypes.string.isRequired,
  showTerms: PropTypes.bool,
  allowAutoComplete: PropTypes.bool,
  showCaptcha: PropTypes.bool,
  children: PropTypes.node.isRequired,
};

AuthBase.defaultProps = {
  showTerms: false,
  allowAutoComplete: false,
  showCaptcha: false,
};

export default observer(AuthBase);
