<?php

use SIUToba\rest\seguridad\autenticacion\validador_jwt;
use Firebase\Auth\Token\Verifier;
use Firebase\Auth\Token\HttpKeyStore;

class toba_usuarios_rest_firebase extends validador_jwt
{
	protected $modelo_proyecto;
	protected $verifier;

    private $keys_urls;
    private $usuario_id;
    private $issuers;
    private $proyecto_id;

	function __construct(\toba_modelo_proyecto $proyecto)
	{
        $this->modelo_proyecto = $proyecto;
        $this->cargar_ini_firebase();

        $keyStore = new HttpKeyStore(null, null, $this->keys_urls);
        $this->verifier = new Verifier($this->proyecto_id, $keyStore, null, $this->issuers);
    }

    private function cargar_ini_firebase()
    {
        //--- Levanto la CONFIGURACION de jwt.ini
        $ini = toba_modelo_rest::get_ini_server($this->modelo_proyecto);

        $this->keys_urls = explode(',', $ini->get('firebase', 'keys_urls', null, true));
        $this->issuers = explode(',', $ini->get('firebase', 'issuers', null, true));
        $this->usuario_id = $ini->get('firebase', 'usuario_id', null, true);
        $this->proyecto_id = $ini->get('firebase', 'proyecto_id', null, true);
    }

    /**
     * Retorna el usuario
     */
    public function get_usuario($token)
    {
        try {
            $verifiedIdToken = $this->verifier->verifyIdToken($token);
            return $this->get_usuario_jwt($verifiedIdToken);
        } catch (\Firebase\Auth\Token\Exception\ExpiredToken $e) {
            echo $e->getMessage();
        } catch (\Firebase\Auth\Token\Exception\IssuedInTheFuture $e) {
            echo $e->getMessage();
        } catch (\Firebase\Auth\Token\Exception\InvalidToken $e) {
            echo $e->getMessage();
        } catch (Exception $e) {
            echo $e->getMessage();
        }
    }

    public function get_usuario_jwt($data)
    {
        $uid = $data->getClaim($this->usuario_id);
        return $uid;
    }
}

?>
