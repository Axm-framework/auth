<?php

namespace Axm\Auth;

use Axm;

/**
 * Class Application
 *
 * @author  Juan Cristobal <juancristobalgd1@gmail.com>
 * @package Axm\Auth
 */

class Auth
{
  protected $userClass;
  protected $usernameField;
  protected $passwordField;
  protected $session;
  protected $maxFailedAttempts = 5;
  protected $failedAttempts    = 0;

  protected $primaryKey;
  protected $userId;
  protected $user;
  protected $userModel;

  const EVENT_BEFORE_AUTH = 'beforeAuth';
  const EVENT_AFTER_AUTH  = 'afterAuth';


  public function __construct(string $usernameField = 'email', string $passwordField = 'password')
  {
    $this->session       = Axm::app()->session;
    $this->userId        = Axm::app()->config()->get('userId');
    $this->userClass     = Axm::app()->config()->get('userClass');
    $this->primaryKey    = Axm::app()->config()->get('userClass')::primaryKey();

    $this->usernameField = $usernameField;
    $this->passwordField = $passwordField;
  }

  /**
   * Realiza un intento de inicio de sesión con las credenciales proporcionadas.
   * Retorna verdadero si el inicio de sesión fue exitoso, falso en caso contrario.
   */
  public function attempt($username, $password)
  {
    if ($this->failedAttempts >= $this->maxFailedAttempts) {
      throw new \Exception("Has alcanzado el número máximo de intentos fallidos.");
    }

    $this->userModel = $this->userClass::findOne([$this->usernameField => $username]);

    if (!$this->userModel || !password_verify($password, $this->userModel->{$this->passwordField})) {
      ++$this->failedAttempts;

      return false;
    }

    $this->failedAttempts = 0;
    $this->session->set($this->userId, $this->userModel->{$this->primaryKey});

    return true;
  }

  /**
   * Verifica si hay un usuario autenticado actualmente.
   * Retorna verdadero si hay un usuario autenticado, falso en caso contrario.
   */
  public function check(): bool
  {
    return $this->session->has($this->userId);
  }

  /**
   * Retorna el usuario autenticado actualmente o nulo si no hay un usuario autenticado.
   */
  public function user()
  {
    if (!$this->check()) return null;

    return $this->userModel;
  }

  /**
   * Cierra la sesión del usuario actual.
   */
  public function logout()
  {
    $this->session->remove($this->userId);
  }

  /**
   * Retorna el número máximo de intentos fallidos permitidos.
   */
  public function getMaxFailedAttempts()
  {
    return $this->maxFailedAttempts;
  }

  /**
   * Establece el número máximo de intentos fallidos permitidos.
   */
  public function setMaxFailedAttempts($maxFailedAttempts)
  {
    $this->maxFailedAttempts = $maxFailedAttempts;
  }

  /**
   * Retorna el número de intentos fallidos realizados en el inicio de sesión actual.
   */
  public function getFailedAttempts()
  {
    return $this->failedAttempts ?? null;
  }

  /**
   * Create user
   */
  public function loginUser(): void
  {
    $this->session->set($this->userId, $this->userModel->{$this->primaryKey});
    $this->session->set('user', $this->userModel, true);
  }
}
