<?
require_once('comando_toba.php');

class comando_doc extends comando_toba
{
	static function get_info()
	{
		return 'Administracion de la documentación de Toba';
	}
	
	function mostrar_observaciones()
	{
		$this->consola->mensaje("INVOCACION: toba doc OPCION");
		$this->consola->enter();
	}

	/**
	 * Descarga la documentación online del wiki desde desarrollos2.siu.edu.ar utilizando httracker
	 */
	function opcion__wiki()
	{
		$destino = toba_dir().'/proyectos/toba_editor/www/doc/wiki';		
		$lista = manejador_archivos::get_archivos_directorio($destino, "/\\.html/", true);
		foreach ($lista as $arch) {
			unlink($arch);
		}

				
		$comando = 'httrack "https://localhost/trac/toba/wiki" -v  -%h -%F "" -I0 -N100 -x %P -O "'.$destino.'" \
					+*.png +*.gif +*.jpg +*.css +*.js  -*login* -*changeset* -*timeline* -*browse* -*roadmap* \
					-*report* -*search* -*history* -*format* -*settings*  -*about* -*ticket* -*query* -*milestone* \
					-*WikiMacros* -*RecentChanges* -*Desarrollo*';
		system($comando);

		//-- Busca el archivo css del wik y modifica algunos estilos
		$cambios = "
			#altlinks, #search, #header, #metanav, #ctxtnav, #mainnav {
				display: none;
			}
			#footer {
				display: none;
			}
		";
		$archivo_css = $destino."/trac/toba/chrome/common/css/trac.css";
		file_put_contents($archivo_css, $cambios, FILE_APPEND);
		
		//$this->convertir_codificacion_dir($destino, "ISO-8859-1", "UTF-8");
	}
	
	/**
	 * Genera la documentación del API en base a los tags phpdoc del código
	 */
	function opcion__api()
	{
		$dest = toba_dir().'/proyectos/toba_editor/www/doc/api';
		$lista = manejador_archivos::get_archivos_directorio($dest, "/\\.html/", true);
		foreach ($lista as $arch) {
			unlink($arch);
		}
		
		//--- Se incluye a phpdocumentor en el path
		$dir = toba_dir()."/php/3ros";
		$separador = (substr(PHP_OS, 0, 3) == 'WIN') ? ";.;" : ":.:";
		ini_set("include_path", ini_get("include_path"). $separador . $dir);
		
		global $_phpDocumentor_setting;
		$_phpDocumentor_setting['title'] = "API de SIU-Toba";
		$_phpDocumentor_setting['directory'] = toba_dir().'/php/nucleo/,'.toba_dir().'/php/lib/,';
		//$_phpDocumentor_setting['directory'] = toba_dir().'/php/nucleo/componentes/interface/efs';
		$_phpDocumentor_setting['target'] = $dest;
		$_phpDocumentor_setting['output'] = "HTML:Smarty:toba_hands";
		$_phpDocumentor_setting['defaultpackagename'] = 'Centrales';
		$_phpDocumentor_setting['customtags'] = 'jsdoc,wiki';
		//$_phpDocumentor_setting['output'] = "HTML:frames:DOM/toba";
		$_phpDocumentor_setting['ignore'] = 'componente*.php';
		require_once("PhpDocumentor/phpDocumentor/phpdoc.inc");
		
		$this->convertir_codificacion_dir($dest, "ISO-8859-1", "UTF-8");		
	}

	/**
	 * Genera la documentación del API Javascript
	 * Utiliza jsdoc (http://jsdoc.sourceforge.net/)
	 */	
	function opcion__api_js()
	{
		$destino = toba_dir().'/proyectos/toba_editor/www/doc/api_js';
		$lista = manejador_archivos::get_archivos_directorio($destino, "/\\.html/", true);
		foreach ($lista as $arch) {
			unlink($arch);
		}
			
		$directorios = toba_dir().'/www/js/basicos ';
		$directorios .= toba_dir().'/www/js/componentes ';
		$directorios .= toba_dir().'/www/js/efs/ef* ';
		
		$cmd = "perl ".toba_dir().
				"/bin/herramientas/JSDoc/jsdoc.pl --globals-name GLOBALES ".
				"--recursive --directory $destino --no-sources ".
				"--project-name \"SIU-Toba\" $directorios ";
		system($cmd);
		$this->convertir_codificacion_dir($destino, "ISO-8859-1", "UTF-8");
	}
	

	protected function convertir_codificacion($archivo, $desde, $hasta)
	{	
		$this->consola->mensaje_directo(".");
		$utf8 = file_get_contents($archivo);
		$iso = iconv($desde, $hasta, $utf8);
		file_put_contents($archivo, $iso);
	}

	
	protected function convertir_codificacion_dir($destino, $desde="UTF-8", $hasta="ISO-8859-1")
	{
		//Se buscan los archivos .html del arbol de directorios
		$archivos = manejador_archivos::get_archivos_directorio($destino, "/\\.html/", true);
		$cant = count($archivos);
		$this->consola->mensaje("Convirtiendo $cant archivos de codificacion $desde a $hasta:");		
		foreach ($archivos as $archivo) {
			$this->convertir_codificacion($archivo, $desde, $hasta);
		}
		$this->consola->mensaje("Fin conversión");
	}
}
?>